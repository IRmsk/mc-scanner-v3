# -*- coding: utf-8 -*-
"""
AI 内容生成模块。
支持 OpenAI 兼容 API，可生成小说故事、名人简介、自定义主题文本。
生成长文本自动按 MC 聊天长度限制（256字符）分段。
"""
import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

# 预设生成模板
PRESETS = {
    "novel": {
        "label": "小说故事",
        "system": "你是一位擅长短篇故事创作的作家，写的故事引人入胜、情节紧凑。",
        "template": "请以「{topic}」为主题，写一篇300字左右的短篇故事，要求有开头、发展、结尾，语言生动。",
    },
    "fairy": {
        "label": "童话",
        "system": "你是一位童话作家，擅长写温馨奇幻的童话故事，语言生动有趣。",
        "template": "请以「{topic}」为主题，写一篇300字左右的童话故事，要有奇幻元素和温暖结局。",
    },
    "horror": {
        "label": "恐怖故事",
        "system": "你是一位恐怖小说作家，擅长营造紧张诡异的氛围。",
        "template": "请以「{topic}」为主题，写一篇300字左右的恐怖短篇，氛围诡异，结局反转。",
    },
    "funny": {
        "label": "搞笑段子",
        "system": "你是一位搞笑段子手，擅长写幽默爆笑的小故事。",
        "template": "请以「{topic}」为主题，写一篇300字左右的搞笑故事，要有梗有反转，让人笑出声。",
    },
    "epic": {
        "label": "史诗传奇",
        "system": "你是一位史诗作家，擅长写宏大叙事的传奇故事。",
        "template": "请以「{topic}」为主题，写一篇300字左右的史诗故事，气势磅礴，有英雄、冒险和战斗。",
    },
    "celebrity": {
        "label": "名人简介",
        "system": "你是一位知识渊博的传记作家，擅长用简洁生动的语言介绍名人。",
        "template": "请介绍名人「{topic}」的生平、主要成就和历史影响，300字左右，语言通俗易懂。",
    },
    "poem": {
        "label": "诗词",
        "system": "你是一位诗人，擅长创作各种风格的诗歌。",
        "template": "请以「{topic}」为主题创作一首诗，风格不限，要求意境优美。",
    },
    "speech": {
        "label": "演讲稿",
        "system": "你是一位演讲撰稿人，擅长写有感染力的演讲稿。",
        "template": "请以「{topic}」为主题写一篇简短的演讲稿，300字左右，有号召力。",
    },
    "joke": {
        "label": "笑话段子",
        "system": "你是一位幽默大师，擅长讲各种笑话。",
        "template": "请讲一个关于「{topic}」的笑话，要简短好笑。",
    },
    "custom": {
        "label": "自定义",
        "system": "你是一个 helpful 的助手。",
        "template": "{topic}",
    },
}

# MC 聊天单条最大长度（留余量）
MC_CHAT_MAX = 240

# AI API 主机白名单（按域名后缀匹配）。
# 目的：ai_base_url 可通过 /api/config/save 被改动，若不限制，把 base_url 指向
# 攻击者服务器或内网地址（含云元数据 169.254.169.254）即可拿到请求头里的
# Authorization: Bearer <api_key> —— 典型的 SSRF + 凭据外泄。
# 需要接入白名单外的自建/中转端点时，可在配置里加 ai_base_url_allowlist（逗号分隔域名）。
ALLOWED_BASE_URL_SUFFIXES = (
    "openai.com", "deepseek.com", "moonshot.cn", "bigmodel.cn", "aliyuncs.com",
    "siliconflow.cn", "volces.com", "baidubce.com", "anthropic.com", "googleapis.com",
    "x.ai", "groq.com", "mistral.ai", "cohere.ai", "together.xyz", "openrouter.ai",
    "perplexity.ai", "minimaxi.com", "stepfun.com", "sensenova.cn", "hunyuan.tencent.com",
)

# 响应体上限（1MiB）：恶意/被劫持的 API 端点可用超大响应造成内存放大
MAX_RESPONSE_BYTES = 1024 * 1024


def _is_forbidden_ip(ip: str) -> bool:
    """内网/回环/链路本地/保留地址一律拒绝。"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
            or a.is_multicast or a.is_unspecified)


def validate_base_url(base_url: str, allow_insecure: bool = False):
    """校验 AI API 地址，返回 (ok, 规范化地址 或 错误信息)。

    规则：必须 https；主机（含解析结果）不能是内网/回环/链路本地地址；
    主机必须在白名单后缀内（可用配置 ai_base_url_allowlist 追加自定义域名）。
    allow_insecure=True 时放宽：允许 http + 本地/内网地址（用于 Ollama 等本地模型）。
    """
    url = (base_url or "").strip()
    if not url:
        return False, "未配置 AI API 地址"
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception as e:
        return False, f"AI API 地址无法解析: {e}"
    if parsed.scheme not in ("http", "https"):
        return False, f"AI API 地址协议不支持: {parsed.scheme}"
    if parsed.scheme != "https" and not allow_insecure:
        return False, "AI API 地址必须使用 https（拒绝明文 http，避免 API Key 被窃听；本地模型可在设置开启'允许不安全地址'）"
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False, "AI API 地址缺少主机名"
    is_local = _is_forbidden_ip(host)
    if is_local and not allow_insecure:
        return False, f"拒绝访问内网/保留地址: {host}（本地模型可在设置开启'允许不安全地址'）"
    # 域名解析结果也要检查，避免用域名指向内网（SSRF）
    if not is_local:
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
            for info in infos:
                if _is_forbidden_ip(info[4][0]) and not allow_insecure:
                    return False, f"域名解析到内网/保留地址: {host}"
        except Exception as e:
            if not allow_insecure:
                return False, f"AI API 地址无法解析: {host} ({e})"
    # 本地地址跳过白名单检查；公网地址仍需白名单
    if is_local:
        return True, url
    # 白名单后缀匹配
    allowed = [s for s in ALLOWED_BASE_URL_SUFFIXES if s]
    try:
        import config as _cfg
        extra = str(_cfg.get("ai_base_url_allowlist", "") or "").replace(",", " ")
        allowed += [d.strip().lower().lstrip(".") for d in extra.split() if d.strip()]
    except Exception:
        pass
    if not any(host == s or host.endswith("." + s) for s in allowed):
        return False, (f"AI API 主机不在白名单: {host}"
                       "（如需自定义端点，请在配置 ai_base_url_allowlist 中添加该域名）")
    return True, url


def split_for_minecraft(text: str, max_len: int = MC_CHAT_MAX) -> list:
    """把长文本按 MC 聊天长度限制分段，尽量在句号/换行处断开。"""
    lines = text.replace("\r\n", "\n").split("\n")
    result = []
    current = ""
    for line in lines:
        line = line.strip()
        if not line:
            if current:
                result.append(current)
                current = ""
            continue
        # 按句子分割
        sentences = []
        buf = ""
        for ch in line:
            buf += ch
            if ch in "。！？!?；;":
                sentences.append(buf)
                buf = ""
        if buf:
            sentences.append(buf)
        for s in sentences:
            if len(current) + len(s) + 1 <= max_len:
                current += s
            else:
                if current:
                    result.append(current)
                # 单句超长，硬切（用下标步进，替代反复 s = s[max_len:] 的 O(n^2) 拷贝）
                start = 0
                while len(s) - start > max_len:
                    result.append(s[start:start + max_len])
                    start += max_len
                current = s[start:]
    if current:
        result.append(current)
    return [r for r in result if r.strip()]


def generate_content(
    topic: str,
    preset: str = "novel",
    api_key: str = "",
    base_url: str = "https://api.openai.com/v1",
    model: str = "gpt-3.5-turbo",
    custom_prompt: Optional[str] = None,
    custom_system: Optional[str] = None,
    timeout: int = None,
    max_tokens: int = None,
) -> dict:
    """
    调用 AI 生成内容。
    返回: {"success": bool, "text": str, "segments": list, "error": str, "truncated": bool}
    truncated=True表示回复被max_tokens截断，可调用续写
    """
    # timeout/max_tokens 为 None 时从配置读（本地模型可调大超时/调小token）
    try:
        import config as _cfg
        if timeout is None:
            timeout = int(_cfg.get("ai_request_timeout", 180))
        if max_tokens is None:
            max_tokens = int(_cfg.get("ai_max_tokens", 1024))
    except Exception:
        timeout = timeout or 180
        max_tokens = max_tokens or 1024
    if not api_key:
        return {"success": False, "text": "", "segments": [], "error": "未配置 API Key，请在设置中填写 ai_api_key", "truncated": False}

    # 请求发出前先校验地址：只有白名单内的 https 公网主机才会带上 Authorization 头
    try:
        import config as _cfg
        _allow_insecure = bool(_cfg.get("ai_allow_insecure", False))
    except Exception:
        _allow_insecure = False
    _ok, _info = validate_base_url(base_url, allow_insecure=_allow_insecure)
    if not _ok:
        return {"success": False, "text": "", "segments": [], "error": _info, "truncated": False}
    base_url = _info

    preset_cfg = PRESETS.get(preset, PRESETS["custom"])
    system = custom_system or preset_cfg["system"]
    if custom_prompt:
        user_prompt = custom_prompt
    else:
        user_prompt = preset_cfg["template"].format(topic=topic)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.8,
        "max_tokens": max_tokens,
    }

    base = base_url.rstrip("/")
    # 兼容用户填了完整地址（已带/chat/completions）的情况，避免路径重复
    if base.endswith("/chat/completions"):
        url = base
    else:
        url = base + "/chat/completions"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # 限长读取：不设上限时恶意/被劫持端点的超大响应会造成内存放大
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            return {"success": False, "text": "", "segments": [],
                    "error": f"AI 响应体超过 {MAX_RESPONSE_BYTES} 字节上限，已丢弃", "truncated": False}
        data = json.loads(raw.decode("utf-8"))
        choice = data["choices"][0]
        text = choice["message"]["content"].strip()
        finish_reason = choice.get("finish_reason", "stop")
        truncated = (finish_reason == "length")
        segments = split_for_minecraft(text)
        return {"success": True, "text": text, "segments": segments, "error": "", "truncated": truncated}
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            err_body = str(e)
        return {"success": False, "text": "", "segments": [], "error": f"HTTP {e.code}: {err_body[:200]}", "truncated": False}
    except Exception as e:
        return {"success": False, "text": "", "segments": [], "error": str(e), "truncated": False}


def get_preset_list() -> list:
    """返回预设列表，供前端下拉选择。"""
    return [{"key": k, "label": v["label"]} for k, v in PRESETS.items()]
