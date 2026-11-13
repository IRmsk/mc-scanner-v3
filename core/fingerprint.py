# -*- coding: utf-8 -*-
"""
服务端指纹识别扩展（v3.2.1 新增）。
在原版 core_type 检测基础上，增加更细粒度的服务端类型识别：
bungeecord / velocity / node-minecraft-protocol / catserver / mohist / arclight 等。
与原版 probe.py 的 core_type 检测互补，不替换原有逻辑。
"""
import re

# 已知服务端类型及匹配关键词
SERVER_TYPE_PATTERNS = {
    "vanilla": [
        r"^1\.\d+(\.\d+)?$",
    ],
    "paper": [
        r"paper",
        r"git-paper",
    ],
    "spigot": [
        r"spigot",
        r"git-spigot",
    ],
    "bukkit": [
        r"bukkit",
        r"git-bukkit",
    ],
    "purpur": [
        r"purpur",
    ],
    "neoforge": [
        r"neoforge",
    ],
    "forge": [
        r"forge",
        r"fml",
        r"modloader",
    ],
    "fabric": [
        r"fabric",
    ],
    "quilt": [
        r"quilt",
    ],
    "bungeecord": [
        r"bungeecord",
        r"bungee",
        r"waterfall",
        r"travertine",
        r"hexacord",
    ],
    "velocity": [
        r"velocity",
    ],
    "catserver": [
        r"catserver",
    ],
    "mohist": [
        r"mohist",
    ],
    "arclight": [
        r"arclight",
    ],
    "magma": [
        r"magma",
    ],
    "node-minecraft-protocol": [
        r"node-minecraft-protocol",
        r"minecraft-protocol",
        r"nodemc",
    ],
}


def fingerprint_server(slp_info: dict, existing_core_type: str = None) -> dict:
    """
    根据 SLP 响应识别服务端类型。
    优先使用原版已检测的 core_type，再用扩展规则细化。
    返回: {"type": "...", "confidence": float, "source": "core_type|extended|unknown", "details": {...}}
    """
    if not slp_info or not isinstance(slp_info, dict):
        return {"type": existing_core_type or "unknown", "confidence": 0.0, "source": "unknown", "details": {}}

    # version / players 是**远端服务器可控**的字段，类型完全不可信：
    # 恶意或畸形服务器发 {"version": "1.20"} / {"players": []} 就能让这里 AttributeError，
    # 进而把整个扫描线程带崩（调用方大多没有兜底 try）。所以逐个做类型归一化。
    version_info = slp_info.get("version", {})
    if not isinstance(version_info, dict):
        version_info = {}
    version_name = str(version_info.get("name", "") or "").lower()
    description = slp_info.get("description", "")
    motd = _extract_text(description).lower()
    players = slp_info.get("players", {})
    if not isinstance(players, dict):
        players = {}
    sample = players.get("sample", []) or []
    if not isinstance(sample, list):
        sample = []
    sample_names = [str(p.get("name", "")).lower() for p in sample if isinstance(p, dict)]

    details = {
        "version_name": version_info.get("name", ""),
        "protocol": version_info.get("protocol", 0),
        "has_forge_data": "modinfo" in slp_info or "forgeData" in slp_info,
        "sample_players": sample_names[:5],
    }

    # 1. 优先使用原版 core_type（如果已有且不是 unknown）
    if existing_core_type and existing_core_type != "unknown":
        return {
            "type": existing_core_type,
            "confidence": 0.85,
            "source": "core_type",
            "details": details,
        }

    # 2. Forge 数据字段检测
    if "modinfo" in slp_info or "forgeData" in slp_info:
        return {"type": "forge", "confidence": 0.95, "source": "extended", "details": details}

    # 3. 玩家样本中的 FML/Forge 标记
    for name in sample_names:
        if "fml" in name or "forge" in name:
            return {"type": "forge", "confidence": 0.8, "source": "extended", "details": details}
        if "fabric" in name:
            return {"type": "fabric", "confidence": 0.75, "source": "extended", "details": details}

    # 4. 版本名关键词匹配
    best_type = None
    best_confidence = 0.0
    for stype, patterns in SERVER_TYPE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, version_name):
                conf = 0.9 if stype in ("paper", "spigot", "forge", "fabric", "bungeecord", "velocity") else 0.75
                if conf > best_confidence:
                    best_type = stype
                    best_confidence = conf
                break
        if best_type and best_confidence >= 0.9:
            break

    if best_type:
        return {"type": best_type, "confidence": best_confidence, "source": "extended", "details": details}

    # 5. MOTD 关键词匹配（低置信度）
    for stype, patterns in SERVER_TYPE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, motd):
                return {"type": stype, "confidence": 0.5, "source": "extended", "details": details}

    # 6. 纯净版本号 → vanilla
    if re.match(r"^1\.\d+(\.\d+)?$", version_name.strip()):
        return {"type": "vanilla", "confidence": 0.6, "source": "extended", "details": details}

    return {"type": "unknown", "confidence": 0.0, "source": "unknown", "details": details}


def _extract_text(desc) -> str:
    """从 description 字段提取纯文本。"""
    if isinstance(desc, str):
        return desc
    if isinstance(desc, dict):
        parts = []
        if "text" in desc:
            parts.append(desc["text"])
        extra = desc.get("extra")
        if isinstance(extra, list):
            for e in extra:
                parts.append(_extract_text(e))
        return " ".join(parts)
    return str(desc)


# 已知服务端类型列表（用于 Web 面板筛选和 CLI）
KNOWN_SERVER_TYPES = [
    "vanilla", "paper", "spigot", "bukkit", "purpur",
    "forge", "fabric", "quilt", "neoforge",
    "bungeecord", "velocity",
    "catserver", "mohist", "arclight", "magma",
    "node-minecraft-protocol", "unknown",
]
