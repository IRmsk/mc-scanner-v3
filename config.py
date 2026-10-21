# -*- coding: utf-8 -*-
"""
全局统一配置模块。
消除 cli.py / web/app.py 各处硬编码默认值，所有模块从这里取配置。
"""
import json
import os
import tempfile
import threading

# 版本号单一来源：CLI、Web 面板、启动脚本都从这里取，避免各处写死导致不一致。
__version__ = "3.6.5"

DEFAULT_CONFIG = {
    "username": "SecurityBot",
    "messages": None,
    "ports": [25565],
    "scan_threads": 50,
    "scan_timeout": 3.0,
    "workers": 16,            # SLP探测线程数
    "timeout": 5.0,           # SLP探测超时
    "bot_threads": 5,
    "bot_timeout": 15,
    "message_delay": 1.2,
    "retry_count": 1,
    "rate": 30,
    "authme_password": "",
    "exclude_file": "exclude.conf",
    "db_path": "mcscanner.db",
    "auto_save_db": True,
    "output_format": "json",
    "output_file": None,
    "web_host": "127.0.0.1",
    "web_port": 8080,
    "web_token": "",          # Web面板访问token，空=不启用认证
    "api_rate_limit": 600,    # API限流：按IP+模块滑动窗口每分钟请求数，0=关闭
                              # 默认值必须容得下面板轮询（/api/scan/status+tasks 各1次/秒）
    "proxy_test_host": "",        # 代理健康检查目标，默认空=跳过检查；请填自有服务器地址
    "proxy_test_port": 25565,             # 代理健康检查目标端口
    "log_level": "INFO",
    # v3.3 新增
    "discord_webhook": "",     # Discord Webhook URL，空=不启用通知
    "rescan_enabled": False,   # 智能重扫（玩家历史追踪+动态重扫频率）
    "duplicate_detection": False,  # 重复服务器检测
    # AI 内容生成
    "ai_api_key": "",          # AI API Key（OpenAI兼容）
    "ai_base_url": "https://api.deepseek.com/v1",  # AI API 地址
    "ai_model": "deepseek-chat",  # AI 模型名
    "ai_api_keys": [],         # API Key 预设列表: [{"name":"","api_key":"","base_url":"","model":""}]
    "ai_allow_insecure": False,  # 允许HTTP+本地地址（用于Ollama等本地模型，默认关）
    "ai_request_timeout": 180,   # AI请求超时（秒），本地模型慢可调大
    "ai_max_tokens": 1024,       # AI生成最大token数，本地模型可调小加快响应
    "ai_reply_cooldown": 2.0,   # AI 回复冷却（秒）
    # 邮件通知
    "email_enabled": False,     # 扫描完成邮件通知开关
    "email_smtp_host": "",      # SMTP服务器地址，如 smtp.qq.com
    "email_smtp_port": 465,     # SMTP端口，465=SSL, 587=TLS
    "email_smtp_ssl": True,     # 是否使用SSL
    "email_username": "",       # 发件邮箱账号
    "email_password": "",       # 发件邮箱授权码/密码
    "email_from": "",           # 发件人显示名，空=用邮箱地址
    "email_to": "",             # 收件邮箱，多个用逗号分隔
    # 收藏服务器健康监控
    "health_interval": 300,       # 每轮探测间隔秒数（最小60）
    "health_probe_concurrency": 8,  # 同时探测数（不同IP并行；同IP由ip_gap节流）
    "health_probe_ip_gap": 1.5,   # 同IP两次探测最小间隔秒（不同IP不受限；同IP多端口时节流）
    "health_monitor_db_extra": False,  # 是否额外监控数据库里有人气的服（默认关，避免无授权探测第三方服务器）
}

_GLOBAL_CFG = None
_CONFIG_PATH = None

# 配置读改写锁：多个路由并发 set()+save_config() 会互相覆盖内存配置，
# 且直接写目标文件时进程中断会留下半截 JSON（token/密钥全丢）。
_SAVE_LOCK = threading.RLock()


def _apply_env_overrides(cfg: dict) -> dict:
    """环境变量优先覆盖敏感配置，避免密钥写进仓库。"""
    env_map = {
        "MC_WEB_TOKEN": "web_token",
        "MC_AI_API_KEY": "ai_api_key",
        "MC_AI_BASE_URL": "ai_base_url",
        "MC_AI_MODEL": "ai_model",
        "MC_DISCORD_WEBHOOK": "discord_webhook",
        "MC_EMAIL_USERNAME": "email_username",
        "MC_EMAIL_PASSWORD": "email_password",
        "MC_EMAIL_TO": "email_to",
        "MC_AUTHME_PASSWORD": "authme_password",
    }
    for env_key, cfg_key in env_map.items():
        val = os.environ.get(env_key)
        if val is not None and val != "":
            cfg[cfg_key] = val
    return cfg


def load_config(path: str = None) -> dict:
    """加载配置文件，合并到默认配置。重复调用返回缓存。"""
    global _GLOBAL_CFG, _CONFIG_PATH
    if _GLOBAL_CFG is not None and (path is None or path == _CONFIG_PATH):
        return _GLOBAL_CFG

    cfg = DEFAULT_CONFIG.copy()
    config_path = path or "config.json"
    # 默认配置在「当前目录」找不到时，回退到脚本所在目录。
    # 否则 `python3 /path/to/cli.py` 从别的目录执行会静默用默认值，
    # 用户以为自己写的 config.json 生效了，实际全被忽略。
    # 显式 -c 传入的路径不回退；当前目录优先级不变。
    if path is None and not os.path.exists(config_path):
        _repo_cfg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
        if os.path.exists(_repo_cfg):
            config_path = _repo_cfg
    if os.path.exists(config_path):
        # 纠正历史权限：config.json 内含敏感凭据，应为 0600
        try:
            if os.stat(config_path).st_mode & 0o077:
                os.chmod(config_path, 0o600)
                print(f"[!] config.json 权限过宽，已收紧为 0600: {config_path}")
        except OSError:
            pass
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                user_cfg = json.load(f)
            cfg.update(user_cfg)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[!] 配置文件读取失败，使用默认配置: {e}")  # bootstrap, logger may not ready
    cfg = _apply_env_overrides(cfg)
    # 统一路径基准：相对 db_path 锚定到 config.json 所在目录（与 favorites.json 一致），
    # 避免从别的目录运行时 DB 落在 CWD 而收藏在仓库目录。
    _db = cfg.get("db_path") or "mcscanner.db"
    if not os.path.isabs(_db):
        cfg["db_path"] = os.path.join(os.path.dirname(config_path), _db)
    _GLOBAL_CFG = cfg
    _CONFIG_PATH = config_path
    return cfg


def get(key: str, default=None):
    """获取单个配置项，自动加载默认配置。"""
    if _GLOBAL_CFG is None:
        load_config()
    return _GLOBAL_CFG.get(key, default)


def set(key: str, value):
    """运行时覆盖单个配置项（不写入文件）。"""
    if _GLOBAL_CFG is None:
        load_config()
    with _SAVE_LOCK:
        _GLOBAL_CFG[key] = value


def get_all() -> dict:
    """返回全部配置的副本。"""
    if _GLOBAL_CFG is None:
        load_config()
    with _SAVE_LOCK:
        return dict(_GLOBAL_CFG)


def save_config(cfg: dict = None, path: str = None) -> bool:
    """保存配置到文件。cfg为None则保存当前内存配置；传入部分字段时自动合并到完整配置。

    整段（合并内存配置 → 序列化 → 落盘）持锁，并改为「临时文件 → fsync → os.replace」
    原子替换：原实现直接 open(target,"w") 截断后写入，并发保存在此互相覆盖，
    写一半被杀则 config.json 损坏（web_token/AI Key 全部丢失）。
    """
    if _GLOBAL_CFG is None:
        load_config()
    with _SAVE_LOCK:
        if cfg is not None:
            # 合并到完整配置，避免部分保存覆盖其他字段
            _GLOBAL_CFG.update(cfg)
        data = dict(_GLOBAL_CFG)
        target = path or _CONFIG_PATH or "config.json"
        # 保存时把配置文件所在目录下的绝对 db_path 转回相对路径，避免烤进 config.json
        # 基准必须与 load_config 一致（都用配置文件自己的目录），否则子目录配置会叠层
        _db = data.get("db_path", "")
        if _db and os.path.isabs(_db):
            _base = os.path.dirname(os.path.abspath(target))
            try:
                _rel = os.path.relpath(_db, _base)
                if not _rel.startswith(".."):
                    data["db_path"] = _rel
            except ValueError:
                pass
        try:
            directory = os.path.dirname(os.path.abspath(target)) or "."
            fd, tmp = tempfile.mkstemp(prefix=os.path.basename(target) + ".", suffix=".tmp", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, target)
                # config.json 内含 AI Key / 邮箱密码 / 微软 refresh_token，收紧为仅所有者可读写
                try:
                    os.chmod(target, 0o600)
                except OSError:
                    pass
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            return True
        except Exception as e:
            print(f"[!] 保存配置失败: {e}")
            return False


def reload_config(path: str = None) -> dict:
    """强制重新加载配置文件。"""
    global _GLOBAL_CFG, _CONFIG_PATH
    _GLOBAL_CFG = None
    _CONFIG_PATH = None
    return load_config(path)
