"""
liveness.py
-----------
Lightweight liveness check for nodes: attempts a raw TCP connect to
server:port with a short timeout, and records how long the handshake took.

Important honesty note: a successful TCP connect only proves the port is
open and accepting connections. It does NOT prove the proxy protocol
handshake would succeed (wrong password, expired account, or a port that's
open but not actually running the proxy would all still "pass" this check).
Likewise, TCP connect latency is a rough proxy for "how far away / how
congested this path is" -- it is NOT the same as the actual proxied
throughput or the latency you'd see once the encryption handshake and
protocol overhead are added on top. Treat it as a cheap ranking signal, not
a guarantee.
"""

import concurrent.futures
import logging
import socket
import time

logger = logging.getLogger("sub_aggregator.liveness")

DEFAULT_TIMEOUT = 2.0
DEFAULT_MAX_WORKERS = 50

# QUIC/UDP-only protocols: a TCP connect is the WRONG instrument for these.
# A hysteria2 server bound to UDP-only (e.g. 443/UDP without a TCP listener)
# fails every TCP probe even while perfectly alive, so probing them would
# silently delete working nodes. They are passed through unchecked.
UDP_ONLY_TYPES = ("hysteria2", "tuic")


def _tcp_check(server: str, port: int, timeout: float) -> tuple[bool, float | None]:
    """Returns (alive, latency_ms). latency_ms is None when the check failed."""
    if not server or not port:
        return False, None
    start = time.monotonic()
    try:
        with socket.create_connection((server, port), timeout=timeout):
            latency_ms = (time.monotonic() - start) * 1000
            return True, latency_ms
    except OSError:
        return False, None


def check_nodes_alive(
    nodes: list[dict],
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    sort_by_latency: bool = True,
    annotate_latency: bool = False,
) -> tuple[list[dict], int]:
    """Concurrently TCP-checks every node.

    - sort_by_latency: reorders surviving nodes fastest-first. Region
      grouping (regions.py) preserves whatever order it's given, so a
      sorted input means each region's proxy-group also comes out
      fastest-first.
    - annotate_latency: appends " [123ms]" to each surviving node's display
      name. Off by default since it permanently changes names shown in the
      client UI; opt in explicitly.

    UDP-only protocols (see UDP_ONLY_TYPES) are never TCP-probed: they are
    kept unconditionally with latency_ms=None and sort last.

    Returns (alive_nodes, dead_count). Nodes are shallow-copied before any
    mutation (annotation) so the caller's original list/dicts are untouched.
    """
    if not nodes:
        return [], 0

    tcp_items = [(i, n) for i, n in enumerate(nodes) if n.get("type") not in UDP_ONLY_TYPES]
    udp_alive = [dict(n, latency_ms=None) for n in nodes if n.get("type") in UDP_ONLY_TYPES]

    results: dict[int, tuple[bool, float | None]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_idx = {
            pool.submit(_tcp_check, n.get("server"), n.get("port"), timeout): i
            for i, n in tcp_items
        }
        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception:
                logger.debug("liveness check raised for node %s", nodes[idx].get("name"), exc_info=True)
                results[idx] = (False, None)

    alive = []
    for i, node in tcp_items:
        is_alive, latency_ms = results.get(i, (False, None))
        if not is_alive:
            continue
        node = dict(node)  # shallow copy: never mutate the caller's original
        node["latency_ms"] = round(latency_ms) if latency_ms is not None else None
        if annotate_latency and latency_ms is not None:
            node["name"] = f"{node.get('name', node.get('server', ''))} [{round(latency_ms)}ms]"
        alive.append(node)

    alive.extend(udp_alive)  # UDP nodes: kept, latency unknown (None sorts last)

    if sort_by_latency:
        alive.sort(key=lambda n: n.get("latency_ms") if n.get("latency_ms") is not None else float("inf"))

    dead_count = len(nodes) - len(alive)
    return alive, dead_count
