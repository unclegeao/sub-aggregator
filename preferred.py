"""
preferred.py
------------
优选订阅生成：把一个（或一批）节点展开成多个"优选地址"变体——
只替换 `server` 为不同的 CF 优选域名/IP，其余（uuid/sni/host/path/port）保持不变。

用法（app.py 集成后）:
  GET /preferred?link=<vmess|vless|订阅源>&type=v2rayn|clash|singbox
"""

import os

# 内置一批常用 CF 优选域名（按需增删）。也可以从 web_domains.txt 读取。
DEFAULT_DOMAINS = [
    "cf.tencentapp.cn", "saas.sin.fan", "fn.130519.xyz",
    "ct.090227.xyz", "cf.1o.ee", "cdn.2020111.xyz",
    "bestcf.030101.xyz", "cf.877774.xyz", "cfip.1323123.xyz",
    "neko.cloudd.eu.org", "freeyx.cloudflare88.eu.org",
    "speed.marisalnc.com", "icook.hk", "icook.tw",
    "mfa.gov.ua", "time.is", "www.shopify.com",
]

PREFERRED_TXT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_domains.txt")


def load_domains(path: str | None = None) -> list[str]:
    """读取优选域名列表：优先用传入 path，其次用项目内 web_domains.txt，最后用内置默认。"""
    candidates = [path, PREFERRED_TXT]
    for cand in candidates:
        if cand and os.path.exists(cand):
            try:
                with open(cand, encoding="utf-8") as f:
                    doms = []
                    for line in f:
                        line = line.split("#", 1)[0].strip()
                        if line and not line.startswith("*."):
                            doms.append(line)
                    if doms:
                        return doms
            except OSError:
                continue
    return list(DEFAULT_DOMAINS)


def expand_node(node: dict, domains: list[str], port: int | None = None) -> list[dict]:
    """把一个节点展开成多个优选变体（仅替换 server，其他字段不动）。"""
    base_name = node.get("name", node.get("server", ""))
    expanded = []
    for d in domains:
        n = dict(node)
        n["server"] = d
        if port is not None:
            n["port"] = port
        # 名字带上优选域名，方便客户端区分
        n["name"] = f"{base_name}·优选-{d}" if base_name else f"优选-{d}"
        expanded.append(n)
    return expanded


def expand_nodes(nodes: list[dict], domains: list[str], port: int | None = None) -> list[dict]:
    out = []
    for node in nodes:
        out.extend(expand_node(node, domains, port))
    return out


def render(nodes: list[dict], fmt: str = "v2rayn", domains: list[str] | None = None,
           port: int | None = None, max_nodes: int = 0) -> str:
    """展开优选变体并按 fmt 渲染。fmt: v2rayn / clash / singbox
    port: 覆盖所有变体的端口（None=保持原节点端口）
    max_nodes: 每个节点最多生成几个变体（0=全部）
    """
    from converters import to_v2rayn, to_clash, to_singbox
    doms = domains if domains is not None else load_domains()
    if max_nodes and max_nodes > 0:
        doms = doms[:max_nodes]
    expanded = expand_nodes(nodes, doms, port)
    if fmt == "clash":
        return to_clash(expanded)
    if fmt == "singbox":
        return to_singbox(expanded)
    return to_v2rayn(expanded)
