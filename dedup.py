"""
dedup.py
--------
Deduplicates parsed nodes that point at the same underlying proxy.

Multiple subscription sources very commonly re-share the same nodes (e.g.
two airports reselling the same upstream, or the same subscription pasted
twice). Without dedup, the aggregated output balloons with exact duplicates
that only differ by display name.

The dedup key deliberately ignores the display name and cosmetic fields
(sni/host/path are kept when they'd actually produce a different
connection, e.g. two vmess entries with the same uuid but different paths
are NOT the same node).
"""


def _dedup_key(node: dict) -> tuple:
    t = node.get("type")
    server = (node.get("server") or "").strip().lower()
    port = node.get("port")

    if t == "vless":
        return (t, server, port, node.get("uuid"), node.get("type_net"), node.get("path"))
    if t == "vmess":
        return (t, server, port, node.get("uuid"), node.get("network"), node.get("path"))
    if t == "trojan":
        return (t, server, port, node.get("password"), node.get("type_net"), node.get("path"))
    if t == "ss":
        return (t, server, port, node.get("cipher"), node.get("password"))
    if t == "hysteria2":
        return (t, server, port, node.get("password"))
    if t == "tuic":
        return (t, server, port, node.get("uuid"), node.get("password"))
    if t == "anytls":
        return (t, server, port, node.get("password"))
    return (t, server, port, node.get("name"))


def dedup_nodes(nodes: list[dict]) -> tuple[list[dict], int]:
    """Removes exact-duplicate nodes, keeping the first occurrence (so the
    first source listed wins on naming). Returns (deduped_nodes, removed_count)."""
    seen = set()
    result = []
    for node in nodes:
        key = _dedup_key(node)
        if key in seen:
            continue
        seen.add(key)
        result.append(node)
    return result, len(nodes) - len(result)
