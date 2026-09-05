"""
parsers.py
----------
Parses individual proxy node URIs (vless/vmess/trojan/ss/hysteria2/tuic/anytls)
into a normalized dict shape used by converters.py.

Design notes:
- Every parser returns None on failure instead of raising, so one malformed
  node in a big pasted list never takes down the whole batch. Callers should
  collect (parsed_count, skipped_count) and surface skipped_count to the user
  instead of silently dropping data.
- Fields are normalized to a common schema:
    {
        "type": "vless" | "vmess" | "trojan" | "ss" | "hysteria2" | "tuic" | "anytls",
        "name": str,
        "server": str,
        "port": int,
        ... protocol-specific fields ...
    }
"""

import base64
import json
import logging
import re
from urllib.parse import urlparse, unquote

logger = logging.getLogger("sub_aggregator.parsers")


def _b64_decode(s: str) -> str:
    s = s.strip()
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding).decode("utf-8", errors="replace")


def _parse_query(query: str) -> dict:
    """Parse URI query params keeping '+' as a literal character.

    parse_qs() applies HTML-form rules and silently rewrites every '+' to a
    space. Node URIs are not forms: hysteria2 obfs-passwords (and similar
    random secrets) are base64-alphabet strings that legitimately contain
    '+', and a mangled value fails the handshake with no visible error.
   Manual split + unquote() keeps '+' intact.
    """
    params = {}
    for pair in query.split("&"):
        if not pair:
            continue
        key, sep, value = pair.partition("=")
        if sep:
            params.setdefault(unquote(key), unquote(value))
    return params


def _userinfo(value: str | None) -> str:
    """Percent-decode a userinfo field (uuid/password) back to its raw form.

    Many generators percent-encode special characters in passwords (e.g.
    '+=' as '%2B%3D'); clash/sing-box consumers need the raw password, and
    converters.py re-encodes when re-emitting URIs for v2rayN.
    """
    return unquote(value) if value else ""


def _safe_int(v, default=443):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def parse_vless(uri: str) -> dict | None:
    try:
        parsed = urlparse(uri)
        if parsed.scheme != "vless":
            return None
        uuid = _userinfo(parsed.username)
        server = parsed.hostname
        port = _safe_int(parsed.port)
        qs = _parse_query(parsed.query)
        name = unquote(parsed.fragment) if parsed.fragment else server
        return {
            "type": "vless",
            "name": name,
            "server": server,
            "port": port,
            "uuid": uuid,
            "flow": qs.get("flow", ""),
            "encryption": qs.get("encryption", "none"),
            "security": qs.get("security", "none"),
            "sni": qs.get("sni", ""),
            "fp": qs.get("fp", ""),
            "pbk": qs.get("pbk", ""),
            "sid": qs.get("sid", ""),
            "type_net": qs.get("type", "tcp"),  # transport: tcp/ws/grpc/h2
            "host": qs.get("host", ""),
            "path": qs.get("path", ""),
            "serviceName": qs.get("serviceName", ""),
        }
    except Exception:
        logger.debug("failed to parse vless uri", exc_info=True)
        return None


def parse_vmess(uri: str) -> dict | None:
    try:
        if not uri.startswith("vmess://"):
            return None
        raw = uri[len("vmess://"):]
        payload = json.loads(_b64_decode(raw))
        return {
            "type": "vmess",
            "name": payload.get("ps") or payload.get("add"),
            "server": payload.get("add"),
            "port": _safe_int(payload.get("port")),
            "uuid": payload.get("id"),
            "alterId": _safe_int(payload.get("aid", 0), default=0),
            "cipher": payload.get("scy", "auto"),
            "network": payload.get("net", "tcp"),
            "tls": payload.get("tls", ""),
            "sni": payload.get("sni", ""),
            "host": payload.get("host", ""),
            "path": payload.get("path", ""),
            "alpn": payload.get("alpn", ""),
        }
    except Exception:
        logger.debug("failed to parse vmess uri", exc_info=True)
        return None


def parse_trojan(uri: str) -> dict | None:
    try:
        parsed = urlparse(uri)
        if parsed.scheme != "trojan":
            return None
        qs = _parse_query(parsed.query)
        name = unquote(parsed.fragment) if parsed.fragment else parsed.hostname
        return {
            "type": "trojan",
            "name": name,
            "server": parsed.hostname,
            "port": _safe_int(parsed.port),
            "password": _userinfo(parsed.username),
            "sni": qs.get("sni", ""),
            "allowInsecure": qs.get("allowInsecure", "0") in ("1", "true"),
            "type_net": qs.get("type", "tcp"),
            "host": qs.get("host", ""),
            "path": qs.get("path", ""),
        }
    except Exception:
        logger.debug("failed to parse trojan uri", exc_info=True)
        return None


def parse_ss(uri: str) -> dict | None:
    """Handles both modern (SIP002, ss://method:pass@host:port) and legacy
    (ss://base64(method:pass@host:port)) shadowsocks link formats."""
    try:
        if not uri.startswith("ss://"):
            return None
        body = uri[len("ss://"):]
        name = ""
        if "#" in body:
            body, frag = body.split("#", 1)
            name = unquote(frag)

        if "@" in body:
            # SIP002: base64(method:pass)@host:port  OR method:pass@host:port
            userinfo, hostport = body.split("@", 1)
            try:
                userinfo = _b64_decode(userinfo)
            except Exception:
                pass  # already plaintext
            method, _, password = userinfo.partition(":")
            hostport = hostport.split("?")[0].split("/")[0]
            host, _, port = hostport.rpartition(":")
            # urlparse() strips IPv6 brackets for every other protocol, so strip
            # them here too. Leaving "[2001:db8::1]" in node["server"] corrupts
            # the Clash/sing-box output (both want a bare address) and makes
            # liveness.py's socket.create_connection fail.
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
        else:
            # Legacy: entire method:pass@host:port is base64-encoded
            decoded = _b64_decode(body)
            creds, _, hostport = decoded.rpartition("@")
            method, _, password = creds.partition(":")
            host, _, port = hostport.rpartition(":")

        return {
            "type": "ss",
            "name": name or host,
            "server": host,
            "port": _safe_int(port),
            "cipher": method,
            "password": password,
        }
    except Exception:
        logger.debug("failed to parse ss uri", exc_info=True)
        return None


def parse_hysteria2(uri: str) -> dict | None:
    try:
        parsed = urlparse(uri)
        if parsed.scheme not in ("hysteria2", "hy2"):
            return None
        qs = _parse_query(parsed.query)
        name = unquote(parsed.fragment) if parsed.fragment else parsed.hostname
        return {
            "type": "hysteria2",
            "name": name,
            "server": parsed.hostname,
            "port": _safe_int(parsed.port),
            "password": _userinfo(parsed.username),
            "sni": qs.get("sni", ""),
            "insecure": qs.get("insecure", "0") in ("1", "true"),
            "obfs": qs.get("obfs", ""),
            "obfs_password": qs.get("obfs-password", ""),
        }
    except Exception:
        logger.debug("failed to parse hysteria2 uri", exc_info=True)
        return None


def parse_tuic(uri: str) -> dict | None:
    try:
        parsed = urlparse(uri)
        if parsed.scheme != "tuic":
            return None
        qs = _parse_query(parsed.query)
        name = unquote(parsed.fragment) if parsed.fragment else parsed.hostname
        uuid = _userinfo(parsed.username)
        password = _userinfo(parsed.password)
        return {
            "type": "tuic",
            "name": name,
            "server": parsed.hostname,
            "port": _safe_int(parsed.port),
            "uuid": uuid,
            "password": password,
            "sni": qs.get("sni", ""),
            "alpn": qs.get("alpn", ""),
            "congestion_control": qs.get("congestion_control", "bbr"),
            "udp_relay_mode": qs.get("udp_relay_mode", "native"),
            "allow_insecure": qs.get("allow_insecure", "0") in ("1", "true"),
        }
    except Exception:
        logger.debug("failed to parse tuic uri", exc_info=True)
        return None


def parse_anytls(uri: str) -> dict | None:
    try:
        parsed = urlparse(uri)
        if parsed.scheme != "anytls":
            return None
        qs = _parse_query(parsed.query)
        name = unquote(parsed.fragment) if parsed.fragment else parsed.hostname
        return {
            "type": "anytls",
            "name": name,
            "server": parsed.hostname,
            "port": _safe_int(parsed.port),
            "password": _userinfo(parsed.username),
            "sni": qs.get("sni", ""),
            "insecure": qs.get("insecure", "0") in ("1", "true"),
        }
    except Exception:
        logger.debug("failed to parse anytls uri", exc_info=True)
        return None


_PARSERS_BY_SCHEME = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_ss,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "tuic": parse_tuic,
    "anytls": parse_anytls,
}


def parse_node_uri(uri: str) -> dict | None:
    uri = uri.strip()
    if not uri:
        return None
    scheme = uri.split("://", 1)[0].lower() if "://" in uri else ""
    parser = _PARSERS_BY_SCHEME.get(scheme)
    if not parser:
        return None
    return parser(uri)


def parse_node_lines(text: str) -> tuple[list[dict], int]:
    """Parse a block of newline-separated node URIs.
    Returns (parsed_nodes, skipped_count) so callers can report data loss
    instead of silently swallowing malformed lines."""
    nodes = []
    skipped = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        node = parse_node_uri(line)
        if node is None:
            skipped += 1
        else:
            nodes.append(node)
    return nodes, skipped


def looks_like_node_uri(line: str) -> bool:
    """True if the line starts with a known proxy node scheme."""
    line = line.strip()
    return any(line.startswith(f"{scheme}://") for scheme in _PARSERS_BY_SCHEME)


# Scheme list built from the parser registry (longest first so e.g.
# "hysteria2" sorts before "hy2" would if they ever overlapped).
_NODE_SCHEME_SPLIT_RE = re.compile(
    r"(?=(" + "|".join(sorted(_PARSERS_BY_SCHEME, key=len, reverse=True)) + r")://)"
)


def _split_cramped_nodes(text: str) -> list[str]:
    """Split a single-line node list that has no separators between URIs.

    The naive approach (split at every scheme:// occurrence) misfires because
    the "ss" inside "vless://" or "vmess://" is itself a scheme prefix and
    would produce a bogus split point. We therefore drop any match that is
    actually the tail of a longer known scheme."""
    parts = []
    last = 0
    for m in _NODE_SCHEME_SPLIT_RE.finditer(text):
        pos = m.start()
        scheme = m.group(1)
        is_fake = any(
            len(t) > len(scheme) and text.startswith(t + "://", pos - (len(t) - len(scheme)))
            for t in _PARSERS_BY_SCHEME
        )
        if is_fake:
            continue
        parts.append(text[last:pos].strip())
        last = pos
    parts.append(text[last:].strip())
    return [p for p in parts if p]


def parse_node_text(text: str) -> tuple[list[dict], int]:
    """Parse node URIs from a block that is either newline-separated or crammed
    onto a single line with no separators (some airports ship base64-decodable
    subscriptions in that compact form). Returns (nodes, skipped_count)."""
    text = text.strip()
    if not text:
        return [], 0
    if "\n" not in text:
        # 单行且出现多个节点 scheme 前缀 -> 紧凑拼接: 先按边界切分再解析。
        # 不能先试 parse_node_lines: 紧凑串的第一段常能被 urlparse 部分解析
        # 成"脏节点"(第二个节点被吞进 fragment), 会导致提前返回而漏掉后续节点。
        parts = _split_cramped_nodes(text)
        if len(parts) > 1:
            return parse_node_lines("\n".join(parts))
    return parse_node_lines(text)


def decode_base64_nodes(text: str) -> tuple[list[dict], int] | None:
    """If `text` is a base64-encoded node list, decode and parse it.

    Accepts both the standard and URL-safe alphabets. A payload is treated as
    a node list when its first non-empty decoded line is a node URI; otherwise
    None is returned so the caller can fall back to treating `text` as a
    subscription URL or plaintext. Returns (nodes, skipped_count) on success.
    """
    try:
        padding = "=" * (-len(text) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(text + padding, validate=False).decode("utf-8", errors="strict")
            except Exception:
                continue
            first = decoded.strip().splitlines()
            if first and looks_like_node_uri(first[0]):
                return parse_node_text(decoded)
    except Exception:
        pass
    return None
