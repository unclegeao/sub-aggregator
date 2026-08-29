"""
app.py
------
全协议万能订阅聚合器 (Flask 版)

Improvements over the original single-file JSON design:
- SQLite storage instead of a hand-rolled JSON file (storage.py)
- SSRF protection that survives DNS rebinding and redirects (security.py)
- Structured logging + a /health endpoint for uptime monitoring
- Rate limiting on every mutating/expensive route (not just creation)
- Admin token required by default in production (warns loudly if unset)
- Response size caps and a max-nodes-per-request limit
- Clear, typed error responses instead of bare 500s
"""

import logging
import os
import secrets
import string
import sys
import threading
import time

try:
    from dotenv import load_dotenv

    load_dotenv()  # 本地开发: 读取 .env 中的配置(StackHost 上由平台注入环境变量)
except ImportError:
    pass

from flask import Flask, request, jsonify, Response, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import storage
from parsers import looks_like_node_uri, parse_node_text, decode_base64_nodes
from converters import to_v2rayn, to_clash, to_singbox
from security import safe_fetch, SSRFBlocked
from dedup import dedup_nodes
from liveness import check_nodes_alive, DEFAULT_TIMEOUT as LIVENESS_TIMEOUT_DEFAULT

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PORT = int(os.environ.get("PORT", 8080))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SHORT_LINK_TTL_DAYS = int(os.environ.get("SHORT_LINK_TTL_DAYS", 30))
CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", 300))
MAX_URLS_PER_REQUEST = int(os.environ.get("MAX_URLS_PER_REQUEST", 200))
MAX_NODES_TOTAL = int(os.environ.get("MAX_NODES_TOTAL", 5000))
LIVENESS_CHECK_TIMEOUT = float(os.environ.get("LIVENESS_CHECK_TIMEOUT", LIVENESS_TIMEOUT_DEFAULT))
LIVENESS_MAX_WORKERS = int(os.environ.get("LIVENESS_MAX_WORKERS", 50))
CODE_ALPHABET = string.ascii_lowercase + string.digits

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("sub_aggregator")

if not ADMIN_TOKEN:
    logger.warning(
        "ADMIN_TOKEN is not set. /create_short is UNAUTHENTICATED and this "
        "instance can be used by anyone as a free relay/converter. "
        "Set ADMIN_TOKEN before exposing this publicly."
    )

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["60 per minute"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _gen_code(length: int = 8) -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))


def _check_admin_token():
    if not ADMIN_TOKEN:
        return  # no token configured -> open instance (already warned at boot)
    supplied = request.headers.get("X-Admin-Token") or request.args.get("token", "")
    if not secrets.compare_digest(supplied, ADMIN_TOKEN):
        abort(401, description="Invalid or missing admin token")


def _extract_nodes_from_source(source: str) -> tuple[list[dict], int]:
    """A `source` entry is either:
      - a raw node URI directly (newline-separated, or crammed without
        newlines into a single line),
      - a base64-encoded node list pasted directly (common airport format), or
      - a subscription URL that (once fetched) contains either base64-encoded
        node URIs or plaintext node URIs, one per line.
    Returns (nodes, skipped_count).
    """
    source = source.strip()
    if not source:
        return [], 0

    # 1) 条目本身是节点 URI(纯文本, 支持多行或单行紧凑拼接)
    if looks_like_node_uri(source):
        return parse_node_text(source)

    # 2) 条目本身是 base64 编码的节点列表(直接粘贴订阅内容)
    decoded = decode_base64_nodes(source)
    if decoded is not None:
        return decoded

    # 3) 当作订阅 URL 抓取
    try:
        body = safe_fetch(source)
    except SSRFBlocked as e:
        logger.info("blocked fetch for %s: %s", source, e)
        return [], 1
    except Exception as e:
        logger.info("fetch failed for %s: %s", source, e)
        return [], 1

    body = body.strip()
    # 4) 响应体优先按 base64 节点列表解析, 否则按纯文本(含紧凑拼接)
    decoded = decode_base64_nodes(body)
    if decoded is not None:
        return decoded
    return parse_node_text(body)


def _gather_nodes(urls: list[str]) -> tuple[list[dict], int, int]:
    """Returns (nodes, parse_skipped_count, dedup_removed_count).
    Nodes are deduplicated (same server/port/credentials -> kept once,
    first source wins on naming) before being returned."""
    all_nodes: list[dict] = []
    total_skipped = 0
    for u in urls[:MAX_URLS_PER_REQUEST]:
        nodes, skipped = _extract_nodes_from_source(u)
        all_nodes.extend(nodes)
        total_skipped += skipped
        if len(all_nodes) >= MAX_NODES_TOTAL:
            all_nodes = all_nodes[:MAX_NODES_TOTAL]
            break
    deduped, dedup_removed = dedup_nodes(all_nodes)
    return deduped, total_skipped, dedup_removed


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Root landing: a small human-readable page with a node-input form so
    users can paste subscription links / node URIs and get their short link
    and the three client subscription URLs right away."""
    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sub-Aggregator · 订阅聚合器</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; display: flex; justify-content: center; padding: 40px 16px; }
  .card { max-width: 720px; width: 100%; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 32px; }
  h1 { font-size: 22px; margin: 0 0 6px; }
  .ok { color: #4ade80; font-size: 14px; }
  h2 { font-size: 13px; margin: 26px 0 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: .08em; }
  textarea { width: 100%; min-height: 120px; background: #0f172a; color: #e2e8f0; border: 1px solid #334155; border-radius: 8px; padding: 10px; font-size: 13px; box-sizing: border-box; font-family: ui-monospace, Consolas, monospace; resize: vertical; }
  .row { display: flex; gap: 8px; margin-top: 10px; }
  input[type=password] { flex: 1; background: #0f172a; color: #e2e8f0; border: 1px solid #334155; border-radius: 8px; padding: 10px; font-size: 13px; }
  button { background: #2563eb; color: #fff; border: 0; border-radius: 8px; padding: 10px 22px; font-size: 14px; cursor: pointer; }
  button:disabled { opacity: .6; cursor: wait; }
  .sub-row { display: flex; align-items: center; gap: 8px; margin: 8px 0; }
  .lbl { flex: 0 0 64px; font-size: 12px; color: #94a3b8; }
  .sub { flex: 1; background: #0f172a; padding: 8px 10px; border-radius: 6px; color: #93c5fd; font-size: 12px; word-break: break-all; border: 1px solid #334155; }
  .meta { margin-top: 10px; font-size: 12px; color: #94a3b8; }
  .err { margin-top: 10px; color: #f87171; font-size: 13px; background: #0f172a; border: 1px solid #7f1d1d; border-radius: 6px; padding: 8px 10px; }
  ul { margin: 0; padding-left: 18px; }
  li { margin: 6px 0; font-size: 13px; line-height: 1.6; }
  .foot { margin-top: 26px; font-size: 12px; color: #64748b; border-top: 1px solid #334155; padding-top: 12px; }
</style>
</head>
<body>
<div class="card">
  <h1>Sub-Aggregator 订阅聚合器</h1>
  <div class="ok">● 服务运行正常</div>
  <h2>输入订阅源</h2>
  <textarea id="urls" placeholder="每行一个：订阅链接 或 节点链接
支持：vless:// vmess:// trojan:// ss:// hysteria2:// tuic:// anytls://
也支持直接粘贴 base64 编码的订阅内容"></textarea>
  <div class="row">
    <input type="password" id="token" placeholder="Admin Token（服务端设置了才需要填）" autocomplete="off">
    <button id="btn" onclick="create()">生成短链</button>
  </div>
  <div id="result"></div>
  <h2>使用说明</h2>
  <ul>
    <li>粘贴订阅链接或节点后点「生成短链」，一次生成，三种客户端通用</li>
    <li>v2rayN / Clash / sing-box(Karing) 填对应订阅地址即可</li>
    <li>短链 30 天有效，过期后重新生成即可</li>
  </ul>
  <div class="foot">健康检查：<code>/health</code> · 管理接口见仓库 README.md</div>
</div>
<script>
async function create() {
  var urls = document.getElementById('urls').value.split('\\n').map(function(s){return s.trim()}).filter(Boolean);
  if (!urls.length) { alert('请先输入订阅链接或节点'); return; }
  var btn = document.getElementById('btn');
  btn.disabled = true; btn.textContent = '生成中…';
  var token = document.getElementById('token').value.trim();
  var headers = {'Content-Type': 'application/json'};
  if (token) headers['X-Admin-Token'] = token;
  var box = document.getElementById('result');
  try {
    var r = await fetch('/create_short', {method: 'POST', headers: headers, body: JSON.stringify({urls: urls, check_alive: false})});
    var j = await r.json();
    if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
    var base = location.origin;
    box.innerHTML =
      '<h2>生成成功</h2>' +
      '<div class="sub-row"><div class="lbl">v2rayN</div><code class="sub">' + base + j.short_url + '</code></div>' +
      '<div class="sub-row"><div class="lbl">Clash</div><code class="sub">' + base + j.short_url + '?type=clash</code></div>' +
      '<div class="sub-row"><div class="lbl">sing-box</div><code class="sub">' + base + j.short_url + '?type=singbox</code></div>' +
      '<div class="meta">节点 ' + j.nodes + ' 个 · 解析跳过 ' + j.skipped + ' · 去重 ' + j.deduped + (j.dead != null ? ' · 失效 ' + j.dead : '') + ' · 有效期 ' + j.expires_in_days + ' 天</div>';
  } catch (e) {
    box.innerHTML = '';
    var err = document.createElement('div');
    err.className = 'err';
    err.textContent = '失败：' + e.message;
    box.appendChild(err);
  } finally {
    btn.disabled = false; btn.textContent = '生成短链';
  }
}
</script>
</body>
</html>"""
    return Response(html, mimetype="text/html; charset=utf-8")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": time.time(), **storage.stats()})


@app.route("/create_short", methods=["POST"])
@limiter.limit("10 per minute")
def create_short():
    _check_admin_token()

    payload = request.get_json(silent=True) or {}
    urls = payload.get("urls")
    check_alive = bool(payload.get("check_alive", False))
    sort_by_latency = bool(payload.get("sort_by_latency", True))
    annotate_latency = bool(payload.get("annotate_latency", False))

    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "body must be {'urls': [ ... ]} with at least one entry"}), 400
    if len(urls) > MAX_URLS_PER_REQUEST:
        return jsonify({"error": f"too many urls, max {MAX_URLS_PER_REQUEST}"}), 400
    if not all(isinstance(u, str) for u in urls):
        return jsonify({"error": "all entries in 'urls' must be strings"}), 400

    nodes, skipped, dedup_removed = _gather_nodes(urls)
    if not nodes:
        return jsonify({"error": "no valid nodes found in provided urls", "skipped": skipped}), 422

    dead_count = 0
    if check_alive:
        nodes, dead_count = check_nodes_alive(
            nodes, LIVENESS_CHECK_TIMEOUT, LIVENESS_MAX_WORKERS,
            sort_by_latency=sort_by_latency, annotate_latency=annotate_latency,
        )
        if not nodes:
            return jsonify({
                "error": "all nodes failed the liveness check",
                "skipped": skipped, "deduped": dedup_removed, "dead": dead_count,
            }), 422

    code = _gen_code()
    while storage.get_short_link(code) is not None:
        code = _gen_code()

    ttl_seconds = SHORT_LINK_TTL_DAYS * 86400
    storage.create_short_link(code, urls, ttl_seconds, node_count=len(nodes))
    storage.set_cached_nodes(code, nodes)

    logger.info(
        "created short link %s with %d nodes (%d parse-skipped, %d deduped, %d dead)",
        code, len(nodes), skipped, dedup_removed, dead_count,
    )
    return jsonify({
        "short_url": f"/s/{code}",
        "nodes": len(nodes),
        "skipped": skipped,
        "deduped": dedup_removed,
        "dead": dead_count if check_alive else None,
        "expires_in_days": SHORT_LINK_TTL_DAYS,
    })


@app.route("/s/<code>")
@limiter.limit("120 per minute")
def get_subscription(code):
    link = storage.get_short_link(code)
    if link is None:
        abort(404, description="short link not found or expired")

    nodes = storage.get_cached_nodes(code, CACHE_TTL_SECONDS)
    if nodes is None:
        nodes, skipped, dedup_removed = _gather_nodes(link["urls"])
        if skipped or dedup_removed:
            logger.info("refresh for %s: %d parse-skipped, %d deduped", code, skipped, dedup_removed)
        storage.set_cached_nodes(code, nodes)

    fmt = request.args.get("type", "v2rayn")
    try:
        if fmt == "clash":
            return Response(to_clash(nodes), mimetype="text/yaml; charset=utf-8")
        elif fmt == "singbox":
            return Response(to_singbox(nodes), mimetype="application/json; charset=utf-8")
        else:
            return Response(to_v2rayn(nodes), mimetype="text/plain; charset=utf-8")
    except Exception:
        logger.exception("failed to render subscription for %s", code)
        abort(500, description="failed to render subscription")


@app.route("/admin/purge_expired", methods=["POST"])
def admin_purge_expired():
    _check_admin_token()
    count = storage.purge_expired()
    return jsonify({"purged": count})


@app.route("/admin/recheck/<code>", methods=["POST"])
@limiter.limit("10 per minute")
def admin_recheck(code):
    """Re-fetches all sources for an existing short link, dedupes, and
    optionally drops nodes that fail a TCP liveness check, then refreshes
    the cache. Useful for pruning dead nodes from a long-lived short link
    without recreating it (which would change the code)."""
    _check_admin_token()
    link = storage.get_short_link(code)
    if link is None:
        abort(404, description="short link not found or expired")

    payload = request.get_json(silent=True) or {}
    check_alive = bool(payload.get("check_alive", False))
    sort_by_latency = bool(payload.get("sort_by_latency", True))
    annotate_latency = bool(payload.get("annotate_latency", False))

    nodes, skipped, dedup_removed = _gather_nodes(link["urls"])
    dead_count = 0
    if check_alive:
        nodes, dead_count = check_nodes_alive(
            nodes, LIVENESS_CHECK_TIMEOUT, LIVENESS_MAX_WORKERS,
            sort_by_latency=sort_by_latency, annotate_latency=annotate_latency,
        )

    storage.set_cached_nodes(code, nodes)
    logger.info(
        "recheck %s: %d nodes (%d parse-skipped, %d deduped, %d dead)",
        code, len(nodes), skipped, dedup_removed, dead_count,
    )
    return jsonify({
        "nodes": len(nodes), "skipped": skipped, "deduped": dedup_removed,
        "dead": dead_count if check_alive else None,
    })


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(404)
@app.errorhandler(422)
@app.errorhandler(500)
def handle_error(e):
    code = getattr(e, "code", 500)
    description = getattr(e, "description", "internal error")
    return jsonify({"error": description}), code


# ---------------------------------------------------------------------------
# Background housekeeping: purge expired short links every hour.
# ---------------------------------------------------------------------------
def _housekeeping_loop():
    while True:
        time.sleep(3600)
        try:
            purged = storage.purge_expired()
            if purged:
                logger.info("housekeeping: purged %d expired short links", purged)
        except Exception:
            logger.exception("housekeeping loop failed")


if os.environ.get("DISABLE_HOUSEKEEPING") != "1":
    threading.Thread(target=_housekeeping_loop, daemon=True).start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
