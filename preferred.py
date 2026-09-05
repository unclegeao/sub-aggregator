"""
preferred.py
------------
优选订阅生成：把一个（或一批）节点展开成多个"优选地址"变体——
只替换 `server` 为不同的 CF 优选域名/IP，其余（uuid/sni/host/path/port）保持不变。

原理：Argo/CF 隧道节点的流量靠 SNI/Host 路由，因此 server 可以换成任何
「解析到 Cloudflare anycast 网段」的域名；换成 GitHub Pages / S3 这类
非 CF 域名则 TLS 握手必然失败，节点是死的。所以展开前会先做 DNS 核验，
自动剔除失效/非 CF 的优选域名（带进程内缓存，避免每请求重复解析）。

用法（app.py 集成后）:
  GET /preferred?link=<vmess|vless|订阅源>&type=v2rayn|clash|singbox
"""

import ipaddress
import logging
import os
import socket
import threading
import time

logger = logging.getLogger(__name__)

# 内置一批常用 CF 优选域名（按需增删）。也可以从 web_domains.txt 读取。
# 2026-09 实测核验过：全部解析到 Cloudflare anycast 网段。
DEFAULT_DOMAINS = [
    "bestcf.030101.xyz", "cdn.2020111.xyz", "cdn.tzpro.xyz",
    "cdns.doon.eu.org", "cf.0sm.com", "cf.1o.ee",
    "cf.345673.xyz", "cf.877774.xyz", "cfip.1323123.xyz",
    "cloud.panguidc.com", "cloudflare-ip.mofashi.ltd", "cmcc.090227.xyz",
    "cnamefuckxxs.yuchen.icu", "coori.cloudflareaccess.com", "ct.090227.xyz",
    "dns.cloudflare-dns.com", "ehvip.93at.com", "fn.130519.xyz",
    "icook.hk", "icook.tw", "ipdb.api.030101.xyz",
    "links1.cloudflare.com", "mfa.gov.ua", "neko.cloudd.eu.org",
    "saas.sin.fan", "staticdelivery.nexusmods.com", "store.ubi.com",
    "time.is", "www.gco.gov.qa", "www.gov.se",
    "www.gov.ua", "www.shopify.com", "xn--b6gac.eu.org",
]

PREFERRED_TXT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_domains.txt")

# Cloudflare 官方 IPv4/IPv6 网段 (https://www.cloudflare.com/ips/)
_CLOUDFLARE_RAW = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13", "104.24.0.0/14",
    "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20",
    "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
    "198.41.128.0/17",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
CF_NETWORKS = [ipaddress.ip_network(n) for n in _CLOUDFLARE_RAW]

# Cloudflare 边缘实际监听的端口。替换 server 后连接的是 CF 边缘，
# 原端口/覆盖端口不在集合内的变体一律连不上。
CF_EDGE_PORTS = {
    # HTTP: 80, 8080, 8880, 2052, 2082, 2086, 2095
    80, 8080, 8880, 2052, 2082, 2086, 2095,
    # HTTPS: 443, 2053, 2083, 2087, 2096, 8443
    443, 2053, 2083, 2087, 2096, 8443,
}

_DNS_TIMEOUT = 2.0
_VERIFY_TTL_SECONDS = 3600
_verify_cache: dict[str, tuple[float, bool]] = {}
_verify_lock = threading.Lock()


def is_cloudflare_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in CF_NETWORKS)


def domain_on_cloudflare(domain: str) -> bool:
    """域名（或裸 IP）当前是否指向 Cloudflare：要求全部解析记录都落在 CF 网段。

    解析失败视为 False；结果缓存 _VERIFY_TTL_SECONDS，避免每次展开都打 DNS。
    """
    now = time.time()
    with _verify_lock:
        cached = _verify_cache.get(domain)
        if cached and cached[0] > now:
            return cached[1]

    if is_cloudflare_ip(domain):
        ok = True
    else:
        try:
            infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
            ips = {ai[4][0] for ai in infos}
            ok = bool(ips) and all(is_cloudflare_ip(ip) for ip in ips)
        except OSError:
            ok = False

    with _verify_lock:
        _verify_cache[domain] = (now + _VERIFY_TTL_SECONDS, ok)
    return ok


def verify_domains(domains: list[str]) -> list[str]:
    """并行核验优选域名，剔除失效/非 CF 条目。

    全部被剔除时（例如部署机 DNS 不可用/被 fake-ip 劫持）回退原始列表，
    保证功能不因核验环节整体失效。
    """
    if not domains:
        return domains
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(domain_on_cloudflare, domains))
    kept = [d for d, ok in zip(domains, results) if ok]
    if not kept:
        logger.warning("preferred: all %d domains failed the Cloudflare "
                       "verification (DNS broken?), falling back to unfiltered list",
                       len(domains))
        return list(domains)
    dropped = [d for d, ok in zip(domains, results) if not ok]
    if dropped:
        logger.info("preferred: dropped %d dead/non-CF preferred domains: %s",
                    len(dropped), ", ".join(dropped))
    return kept


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


def expand_with_options(nodes: list[dict], port: int | None = None,
                        max_nodes: int = 0, domains: list[str] | None = None) -> list[dict]:
    """按 port/max 展开：max 限制每个节点生成的变体数（0=全部）。
    展开前先核验域名列表，自动剔除失效/非 CF 的条目。"""
    doms = domains if domains is not None else load_domains()
    doms = verify_domains(doms)
    if max_nodes and max_nodes > 0:
        doms = doms[:max_nodes]
    return expand_nodes(nodes, doms, port)


def render(nodes: list[dict], fmt: str = "v2rayn", domains: list[str] | None = None,
           port: int | None = None, max_nodes: int = 0) -> str:
    """展开优选变体并按 fmt 渲染。fmt: v2rayn / clash / singbox
    port: 覆盖所有变体的端口（None=保持原节点端口）
    max_nodes: 每个节点最多生成几个变体（0=全部）
    """
    from converters import to_v2rayn, to_clash, to_singbox
    expanded = expand_with_options(nodes, port, max_nodes, domains)
    if fmt == "clash":
        return to_clash(expanded)
    if fmt == "singbox":
        return to_singbox(expanded)
    return to_v2rayn(expanded)
