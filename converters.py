"""
converters.py
-------------
Renders a list of normalized node dicts (see parsers.py) into the three
output formats the clients expect:
  - v2rayN: base64-encoded newline list of raw node URIs
  - Clash: YAML with a `proxies` list
  - sing-box (Karing): JSON with an `outbounds` list
"""

import base64
import json
from urllib.parse import quote

import yaml

from regions import group_by_region


def _host(server: str) -> str:
    """Bracket-escape an IPv6 literal so it survives a URI round-trip.

    urlparse() strips the brackets when handing us ``hostname``
    (``[2001:db8::1]`` -> ``2001:db8::1``), so on the way back out we must
    add them again. Without this, an IPv6 node re-serialized as
    ``hysteria2://pw@2001:db8::1:443`` is unparseable -- the ':' runs are
    indistinguishable, the whole URI fails, and the node is silently lost
    out of the aggregated subscription.
    """
    s = (server or "").strip()
    if ":" in s and not s.startswith("["):
        return f"[{s}]"
    return s


def _node_to_uri(node: dict) -> str:
    """Re-serialize a normalized node back into its URI form for v2rayN."""
    t = node["type"]
    name = node.get("name", node.get("server", ""))
    server = _host(node.get("server", ""))
    if t == "vless":
        # 必须保留 reality 的 pbk/sid、WS 的 host/path 等连接必需参数,
        # 否则 v2rayN 输出的是连不上的节点。type=tcp 是默认传输, 不写。
        qs = f"encryption={node.get('encryption', 'none')}&security={node.get('security', 'none')}"
        params = {
            "sni": node.get("sni"), "fp": node.get("fp"), "flow": node.get("flow"),
            "type": node.get("type_net") if node.get("type_net") != "tcp" else "",
            "host": node.get("host"), "path": node.get("path"),
            "serviceName": node.get("serviceName"), "pbk": node.get("pbk"), "sid": node.get("sid"),
        }
        for url_key, v in params.items():
            if v:
                qs += f"&{url_key}={v}"
        return f"vless://{node['uuid']}@{server}:{node['port']}?{qs}#{name}"
    if t == "vmess":
        payload = {
            "v": "2", "ps": name, "add": node["server"], "port": str(node["port"]),
            "id": node["uuid"], "aid": str(node.get("alterId", 0)),
            "scy": node.get("cipher", "auto"), "net": node.get("network", "tcp"),
            "tls": node.get("tls", ""), "sni": node.get("sni", ""),
            "host": node.get("host", ""), "path": node.get("path", ""),
            "alpn": node.get("alpn", ""),
        }
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        return f"vmess://{encoded}"
    if t == "trojan":
        parts = []
        if node.get("sni"):
            parts.append(f"sni={node['sni']}")
        if node.get("type_net") and node.get("type_net") != "tcp":
            parts.append(f"type={node['type_net']}")
        if node.get("host"):
            parts.append(f"host={node['host']}")
        if node.get("path"):
            parts.append(f"path={node['path']}")
        qs = ("?" + "&".join(parts)) if parts else ""
        return f"trojan://{quote(node['password'], safe='')}@{server}:{node['port']}{qs}#{name}"
    if t == "ss":
        userinfo = base64.urlsafe_b64encode(
            f"{node['cipher']}:{node['password']}".encode()
        ).decode().rstrip("=")
        return f"ss://{userinfo}@{server}:{node['port']}#{name}"
    if t in ("hysteria2",):
        parts = []
        if node.get("sni"):
            parts.append(f"sni={node['sni']}")
        if node.get("security"):
            parts.append(f"security={node['security']}")
        if node.get("alpn"):
            parts.append(f"alpn={node['alpn']}")
        if node.get("obfs"):
            parts.append(f"obfs={node['obfs']}")
        if node.get("obfs_password"):
            # obfs-password is a random base64-alphabet string: percent-encode
            # it so '+' / '=' survive the URI round-trip (parsers.py unquotes).
            parts.append(f"obfs-password={quote(node['obfs_password'], safe='')}")
        # insecure/allowInsecure and pinSHA256 are mutually meaningful: when
        # the server is cert-pinned (insecure=0) the pin MUST survive or the
        # client can't validate the handshake -> connection times out. This
        # was previously dropped entirely, which is the bug we're fixing.
        parts.append("insecure=1" if node.get("insecure") else "insecure=0")
        if node.get("pinSHA256"):
            parts.append(f"pinSHA256={node['pinSHA256']}")
        qs = ("?" + "&".join(parts)) if parts else ""
        # password is already percent-decoded (parsers.py) -> re-encode it for
        # userinfo so reserved chars ('@', '#', '/', '+', '=') can't corrupt
        # the URI structure.
        pw = quote(node["password"], safe="")
        return f"hysteria2://{pw}@{server}:{node['port']}{qs}#{name}"
    if t == "tuic":
        parts = []
        if node.get("sni"):
            parts.append(f"sni={node['sni']}")
        if node.get("alpn"):
            parts.append(f"alpn={node['alpn']}")
        if node.get("congestion_control"):
            parts.append(f"congestion_control={node['congestion_control']}")
        if node.get("udp_relay_mode"):
            parts.append(f"udp_relay_mode={node['udp_relay_mode']}")
        if node.get("allow_insecure"):
            parts.append("allow_insecure=1")
        qs = ("?" + "&".join(parts)) if parts else ""
        return f"tuic://{node['uuid']}:{quote(node['password'], safe='')}@{server}:{node['port']}{qs}#{name}"
    if t == "anytls":
        parts = []
        if node.get("sni"):
            parts.append(f"sni={node['sni']}")
        if node.get("insecure"):
            parts.append("insecure=1")
        qs = ("?" + "&".join(parts)) if parts else ""
        return f"anytls://{quote(node['password'], safe='')}@{server}:{node['port']}{qs}#{name}"
    return ""


def to_v2rayn(nodes: list[dict]) -> str:
    uris = [u for u in (_node_to_uri(n) for n in nodes) if u]
    blob = "\n".join(uris)
    return base64.b64encode(blob.encode()).decode()


def _clash_proxy(node: dict) -> dict | None:
    t = node["type"]
    base = {"name": node.get("name", node.get("server")), "server": node["server"], "port": node["port"]}
    if t == "vless":
        p = {**base, "type": "vless", "uuid": node["uuid"], "udp": True,
             "flow": node.get("flow", ""), "tls": node.get("security") in ("tls", "reality"),
             "network": node.get("type_net", "tcp")}
        if node.get("sni"):
            p["servername"] = node["sni"]
        if node.get("security") == "reality":
            p["reality-opts"] = {"public-key": node.get("pbk", ""), "short-id": node.get("sid", "")}
        return p
    if t == "vmess":
        return {**base, "type": "vmess", "uuid": node["uuid"], "alterId": node.get("alterId", 0),
                "cipher": node.get("cipher", "auto"), "udp": True,
                "tls": bool(node.get("tls")), "network": node.get("network", "tcp"),
                "servername": node.get("sni", "")}
    if t == "trojan":
        return {**base, "type": "trojan", "password": node["password"], "udp": True,
                "sni": node.get("sni", ""), "skip-cert-verify": node.get("allowInsecure", False)}
    if t == "ss":
        return {**base, "type": "ss", "cipher": node["cipher"], "password": node["password"], "udp": True}
    if t == "hysteria2":
        p = {**base, "type": "hysteria2", "password": node["password"],
             "sni": node.get("sni", ""), "skip-cert-verify": node.get("insecure", False)}
        if node.get("alpn"):
            p["alpn"] = [node["alpn"]]
        # 证书指纹锁定: 没有它, 自签证书 + skip-cert-verify=false 的节点
        # 在 clash 内核里握手校验必然失败, 表现为连接超时。
        if node.get("pinSHA256"):
            p["fingerprint"] = node["pinSHA256"]
        # 只在节点真的带 obfs 时输出键, 避免 clash 内核解析到 obfs: null
        if node.get("obfs"):
            p["obfs"] = node["obfs"]
            if node.get("obfs_password"):
                p["obfs-password"] = node["obfs_password"]
        return p
    if t == "tuic":
        return {**base, "type": "tuic", "uuid": node["uuid"], "password": node["password"],
                "sni": node.get("sni", ""), "congestion-controller": node.get("congestion_control", "bbr"),
                "skip-cert-verify": node.get("allow_insecure", False)}
    if t == "anytls":
        return {**base, "type": "anytls", "password": node["password"],
                "sni": node.get("sni", ""), "skip-cert-verify": node.get("insecure", False)}
    return None


def to_clash(nodes: list[dict]) -> str:
    proxies = [p for p in (_clash_proxy(n) for n in nodes) if p]
    names = [p["name"] for p in proxies]
    region_groups = group_by_region(nodes)

    proxy_groups = [
        {"name": "PROXY", "type": "select",
         "proxies": (list(region_groups.keys()) + ["全部节点"]) or ["DIRECT"]},
        {"name": "全部节点", "type": "select", "proxies": names or ["DIRECT"]},
    ]
    for region, region_names in region_groups.items():
        proxy_groups.append({"name": region, "type": "select", "proxies": region_names})

    config = {
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": ["MATCH,PROXY"],
    }
    return yaml.dump(config, allow_unicode=True, sort_keys=False)


def _singbox_outbound(node: dict) -> dict | None:
    t = node["type"]
    base = {"tag": node.get("name", node.get("server")), "server": node["server"], "server_port": node["port"]}
    if t == "vless":
        ob = {**base, "type": "vless", "uuid": node["uuid"], "flow": node.get("flow", "")}
        if node.get("security") in ("tls", "reality"):
            ob["tls"] = {"enabled": True, "server_name": node.get("sni", "")}
            if node.get("security") == "reality":
                ob["tls"]["reality"] = {"enabled": True, "public_key": node.get("pbk", ""), "short_id": node.get("sid", "")}
        return ob
    if t == "vmess":
        return {**base, "type": "vmess", "uuid": node["uuid"], "alter_id": node.get("alterId", 0),
                "security": node.get("cipher", "auto")}
    if t == "trojan":
        return {**base, "type": "trojan", "password": node["password"],
                "tls": {"enabled": True, "server_name": node.get("sni", "")}}
    if t == "ss":
        return {**base, "type": "shadowsocks", "method": node["cipher"], "password": node["password"]}
    if t == "hysteria2":
        ob = {**base, "type": "hysteria2", "password": node["password"],
              "tls": {"enabled": True, "server_name": node.get("sni", ""), "insecure": node.get("insecure", False)}}
        if node.get("alpn"):
            ob["tls"]["alpn"] = [node["alpn"]]
        # NOTE: sing-box's hysteria2 tls block has no pinned-fingerprint
        # (pinSHA256) equivalent -- it only supports full CA verification or
        # `insecure`. A pinned self-signed node has no faithful sing-box
        # representation; if `insecure` is also false here the node will
        # fail cert verification on sing-box clients regardless.
        if node.get("obfs"):
            # sing-box >= 1.9 的 obfs 配置块。丢了它, 开了混淆的节点在
            # sing-box 系客户端(Karing 等)上握手直接失败。
            ob["obfs"] = {"type": node["obfs"], "password": node.get("obfs_password", "")}
        return ob
    if t == "tuic":
        return {**base, "type": "tuic", "uuid": node["uuid"], "password": node["password"],
                "congestion_control": node.get("congestion_control", "bbr"),
                "tls": {"enabled": True, "server_name": node.get("sni", "")}}
    if t == "anytls":
        return {**base, "type": "anytls", "password": node["password"],
                "tls": {"enabled": True, "server_name": node.get("sni", ""), "insecure": node.get("insecure", False)}}
    return None


def to_singbox(nodes: list[dict]) -> str:
    outbounds = [o for o in (_singbox_outbound(n) for n in nodes) if o]
    tags = [o["tag"] for o in outbounds]
    region_groups = group_by_region(nodes)

    region_selectors = [
        {"type": "selector", "tag": region, "outbounds": region_names or ["direct"]}
        for region, region_names in region_groups.items()
    ]

    config = {
        "outbounds": outbounds + [
            {"type": "selector", "tag": "全部节点", "outbounds": tags or ["direct"]},
            {"type": "selector", "tag": "PROXY",
             "outbounds": (list(region_groups.keys()) + ["全部节点"]) or ["direct"]},
            *region_selectors,
            {"type": "direct", "tag": "direct"},
        ]
    }
    return json.dumps(config, ensure_ascii=False, indent=2)
