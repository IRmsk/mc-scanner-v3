# -*- coding: utf-8 -*-
"""
邮件通知模块。
扫描完成后发送结果摘要到指定邮箱。
支持 SMTP SSL/TLS，兼容 QQ邮箱、163邮箱、Gmail等。
"""
import smtplib
import ssl
from datetime import datetime
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr


def _clean_header(v):
    """邮件头字段过滤 CR/LF：email_to/from 可被面板写入，防头注入（Bcc 注入等）。"""
    return str(v or "").replace("\r", " ").replace("\n", " ").strip()


def _html_escape(s):
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def send_email(subject, body, html=False, cfg=None):
    """
    发送邮件。
    cfg: 配置字典，需包含 smtp_host, smtp_port, smtp_ssl, username, password, from, to
    返回: (success: bool, error: str)
    """
    if cfg is None:
        import config
        cfg = {
            "smtp_host": config.get("email_smtp_host", ""),
            "smtp_port": config.get("email_smtp_port", 465),
            "smtp_ssl": config.get("email_smtp_ssl", True),
            "username": config.get("email_username", ""),
            "password": config.get("email_password", ""),
            "from": config.get("email_from", "") or config.get("email_username", ""),
            "to": config.get("email_to", ""),
        }

    host = _clean_header(cfg.get("smtp_host"))
    if not host or not cfg.get("username") or not cfg.get("password") or not cfg.get("to"):
        return False, "邮件配置不完整（需要SMTP服务器、账号、密码、收件人）"

    # 显式传入会校验证书与主机名的 SSL 上下文。
    # 注意：smtplib 在 context=None 时会回落到 ssl._create_stdlib_context()，
    # 实测 verify_mode=CERT_NONE、check_hostname=False —— 等于完全不校验证书，
    # 中间人可窃取邮箱密码/授权码与邮件内容。必须显式用 create_default_context()。
    ssl_ctx = ssl.create_default_context()
    server = None
    try:
        msg = MIMEMultipart()
        # 发件人格式：显示名 <邮箱地址>，163/QQ等要求From必须包含真实邮箱
        from_name = _clean_header(cfg.get("from") or cfg["username"])
        from_addr = _clean_header(cfg["username"])
        msg["From"] = formataddr((from_name, from_addr))
        msg["To"] = Header(_clean_header(cfg["to"]), "utf-8")
        msg["Subject"] = Header(_clean_header(subject), "utf-8")

        mime_type = "html" if html else "plain"
        msg.attach(MIMEText(body, mime_type, "utf-8"))

        if cfg.get("smtp_ssl", True):
            server = smtplib.SMTP_SSL(host, int(cfg["smtp_port"]), timeout=30, context=ssl_ctx)
        else:
            server = smtplib.SMTP(host, int(cfg["smtp_port"]), timeout=30)
            server.starttls(context=ssl_ctx)

        server.login(cfg["username"], cfg["password"])
        recipients = [r.strip() for r in cfg["to"].split(",") if r.strip()]
        server.sendmail(cfg["username"], recipients, msg.as_string())
        server.quit()
        return True, ""
    except Exception as e:
        return False, str(e)
    finally:
        # login/sendmail 抛异常时原先不会 quit()，连接与本地端口会泄漏；
        # 这里兜底 close（quit 之后 close 是幂等的）。
        if server is not None:
            try:
                server.close()
            except Exception:
                pass


def build_scan_report(results, targets_count, duration_sec, task_id=None):
    """
    根据扫描结果生成邮件正文（HTML格式）。
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(results)
    # 统计
    online = [r for r in results if r.get("players_online", 0) and r.get("players_online", 0) > 0]
    cracked = [r for r in results if r.get("auth") == "cracked"]
    online_count = len(online)
    cracked_count = len(cracked)

    # 有人的服务器列表（卡片式，手机友好）
    online_rows = ""
    for r in sorted(online, key=lambda x: x.get("players_online", 0), reverse=True)[:30]:
        ip = _html_escape(r.get("ip", "?"))
        port = r.get("port", 25565)
        ver = _html_escape(r.get("version", "") or "?")
        players = f"{r.get('players_online', 0)}/{r.get('players_max', 0)}"
        motd = _html_escape((r.get("motd") or "")[:60])
        auth = _html_escape(r.get("auth", "?"))
        # 玩家列表
        player_list = r.get("player_list") or r.get("sample") or []
        if player_list:
            if isinstance(player_list[0], dict):
                names = [_html_escape(p.get("name", "")) for p in player_list if p.get("name")][:10]
            else:
                names = [_html_escape(str(n)) for n in player_list if n][:10]
            player_str = ", ".join(names)
            if len(player_list) > 10:
                player_str += f" 等{len(player_list)}人"
        else:
            player_str = "-"
        online_rows += f"""
        <div style="background:#f8f9fa;border-radius:8px;padding:12px;margin-top:10px;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="font-size:15px;font-weight:bold;color:#1a73e8;">{ip}:{port}</span>
            <span style="font-size:14px;font-weight:bold;color:#e94560;">{players}人</span>
          </div>
          <div style="font-size:12px;color:#888;margin-top:4px;">版本 {ver} · {auth}</div>
          <div style="font-size:13px;color:#555;margin-top:4px;">{motd}</div>
          <div style="font-size:12px;color:#999;margin-top:4px;">在线: {player_str}</div>
        </div>"""

    duration_str = f"{int(duration_sec//60)}分{int(duration_sec%60)}秒" if duration_sec > 60 else f"{int(duration_sec)}秒"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
body{{font-family:Arial,sans-serif;background:#f5f5f5;padding:20px;color:#333}}
.container{{max-width:700px;margin:0 auto;background:#fff;border-radius:8px;padding:24px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}}
h1{{color:#1a73e8;font-size:22px;margin:0 0 16px}}
.stats{{display:flex;gap:16px;margin:16px 0}}
.stat{{flex:1;background:#f0f7ff;border-radius:8px;padding:16px;text-align:center}}
.stat .num{{font-size:28px;font-weight:bold;color:#1a73e8}}
.stat .label{{font-size:12px;color:#666;margin-top:4px}}
table{{width:100%;border-collapse:collapse;margin-top:16px;font-size:13px}}
th{{background:#1a73e8;color:#fff;padding:8px;text-align:left}}
td{{padding:8px;border-bottom:1px solid #eee}}
tr:hover{{background:#f9f9f9}}
.footer{{margin-top:20px;padding-top:16px;border-top:1px solid #eee;color:#999;font-size:12px;text-align:center}}
</style></head><body>
<div class="container">
<h1>MC扫描完成通知</h1>
<p>扫描任务 #{task_id or '-'} 已于 {now} 完成。</p>
<div class="stats">
<div class="stat"><div class="num">{total}</div><div class="label">发现服务器</div></div>
<div class="stat"><div class="num">{online_count}</div><div class="label">有人在线</div></div>
<div class="stat"><div class="num">{cracked_count}</div><div class="label">离线/破解</div></div>
<div class="stat"><div class="num">{duration_str}</div><div class="label">耗时</div></div>
</div>
<p><strong>扫描目标数：</strong>{targets_count}</p>
"""
    if online_rows:
        html += f"""<h3 style="margin-top:20px;font-size:16px;">有人的服务器（前30）</h3>
{online_rows}"""
    else:
        html += "<p style='color:#999;margin-top:16px;'>本次扫描未发现有人的服务器。</p>"

    html += f"""<div class="footer">由 mc-scanner-v3 自动发送 | {now}</div>
</div></body></html>"""
    return html


def notify_scan_complete(results, targets_count, duration_sec, task_id=None):
    """扫描完成后发送邮件通知。失败不抛异常，只打印日志。"""
    try:
        import config
        if not config.get("email_enabled", False):
            return False, "邮件通知未启用"
        subject = f"[MC扫描] 发现{len(results)}个服务器，{len([r for r in results if r.get('players_online',0)>0])}个有人"
        body = build_scan_report(results, targets_count, duration_sec, task_id)
        ok, err = send_email(subject, body, html=True)
        if ok:
            print(f"[邮件通知] 发送成功 -> {config.get('email_to', '')}")
        else:
            print(f"[邮件通知] 发送失败: {err}")
        return ok, err
    except Exception as e:
        print(f"[邮件通知] 异常: {e}")
        return False, str(e)
