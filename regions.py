"""
regions.py
----------
Best-effort region detection from a node's display name, used to build
auto-grouped proxy-groups (Clash) / selectors (sing-box) instead of dumping
every node into a single flat list.

This is inherently heuristic: node names come from whatever the airport/
subscription author chose, so detection is name-based pattern matching, not
a lookup against the node's actual IP geolocation. Nodes that don't match
any known pattern land in the "其他" (Other) bucket instead of being lost.
"""

import re

# Ordered: more specific / less ambiguous patterns first. Chinese names and
# flag emoji are unambiguous substrings; short alpha codes (US/UK/DE...) are
# matched with word boundaries to avoid false positives inside unrelated words.
_REGION_RULES: list[tuple[str, list[str], list[str]]] = [
    # (region_label, substrings (case-insensitive, no boundary needed), word-boundary codes)
    ("香港", ["香港", "hongkong", "hong kong", "🇭🇰"], ["hk"]),
    ("台湾", ["台湾", "臺灣", "taiwan", "🇹🇼"], ["tw"]),
    ("日本", ["日本", "japan", "🇯🇵"], ["jp"]),
    ("韩国", ["韩国", "korea", "🇰🇷"], ["kr"]),
    ("新加坡", ["新加坡", "singapore", "🇸🇬"], ["sg"]),
    ("美国", ["美国", "united states", "america", "🇺🇸"], ["us", "usa"]),
    ("英国", ["英国", "united kingdom", "britain", "🇬🇧"], ["uk", "gb"]),
    ("德国", ["德国", "germany", "🇩🇪"], ["de"]),
    ("法国", ["法国", "france", "🇫🇷"], ["fr"]),
    ("加拿大", ["加拿大", "canada", "🇨🇦"], ["ca"]),
    ("澳大利亚", ["澳大利亚", "澳洲", "australia", "🇦🇺"], ["au"]),
    ("俄罗斯", ["俄罗斯", "russia", "🇷🇺"], ["ru"]),
    ("印度", ["印度", "india", "🇮🇳"], ["in"]),
    ("荷兰", ["荷兰", "netherlands", "🇳🇱"], ["nl"]),
    ("土耳其", ["土耳其", "turkey", "🇹🇷"], ["tr"]),
    ("巴西", ["巴西", "brazil", "🇧🇷"], ["br"]),
    ("马来西亚", ["马来西亚", "malaysia", "🇲🇾"], ["my"]),
    ("阿根廷", ["阿根廷", "argentina", "🇦🇷"], ["ar"]),
]

_OTHER = "其他"


def detect_region(name: str) -> str:
    if not name:
        return _OTHER
    lower = name.lower()
    for label, substrings, codes in _REGION_RULES:
        for s in substrings:
            if s.lower() in lower:
                return label
    for label, _substrings, codes in _REGION_RULES:
        for code in codes:
            if re.search(rf"\b{re.escape(code)}\b", lower):
                return label
    return _OTHER


def group_by_region(nodes: list[dict]) -> dict[str, list[str]]:
    """Returns {region_label: [node_name, ...]} preserving first-seen order
    of both regions and names within each region."""
    groups: dict[str, list[str]] = {}
    for node in nodes:
        name = node.get("name") or node.get("server") or ""
        region = detect_region(name)
        groups.setdefault(region, []).append(name)
    return groups
