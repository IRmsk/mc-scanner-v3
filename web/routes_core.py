# -*- coding: utf-8 -*-
"""Routes: core"""
import html
import os

try:
    from web import state
except ImportError:
    import state  # type: ignore


def register(app):
    def _log(msg):
        state.log_scan(msg)
    def _safe_db_path(path):
        return state.safe_db_path(path)
    def parse_ports_spec(ports_spec):
        return state.parse_ports_spec(ports_spec)


    @app.route('/')
    def index():
        try:
            from web.ui_inject import serve_index
        except ImportError:
            from ui_inject import serve_index
        return serve_index(os.path.dirname(__file__))

    @app.route('/auth-response')
    def auth_response():
        """FCL授权码流程回调：捕获code，完成正版登录"""
        from flask import request

        import config as cfg_mod
        from core.microsoft_auth import fcl_exchange_code, full_login_flow
        code = request.args.get("code", "")
        error = request.args.get("error", "")
        if error:
            return f"<html><body style='font-family:sans-serif;text-align:center;padding-top:50px;'><h2>登录失败</h2><p>{html.escape(str(error))}</p><p>可以关闭此页面返回APP</p></body></html>"
        if not code:
            return "<html><body style='font-family:sans-serif;text-align:center;padding-top:50px;'><h2>缺少授权码</h2><p>可以关闭此页面返回APP</p></body></html>"
        try:
            print(f"[MSA] 收到授权码: {code[:20]}...")
            r = fcl_exchange_code(code)
            if "access_token" not in r:
                err_desc = r.get("error_description", str(r))
                return f"<html><body style='font-family:sans-serif;text-align:center;padding-top:50px;'><h2>换Token失败</h2><p>{html.escape(str(err_desc))}</p><p>可以关闭此页面返回APP</p></body></html>"
            msa_token = r["access_token"]
            print(f"[MSA] 获取MSA token成功: {msa_token[:30]}...")
            result = full_login_flow(msa_token)
            # 保存到config
            cfg = cfg_mod.get_all()
            cfg["msa_access_token"] = result["access_token"]
            cfg["msa_uuid"] = result["uuid"]
            cfg["msa_name"] = result["name"]
            cfg_mod.save_config(cfg)
            print(f"[MSA] 正版登录成功: {result['name']}")
            return f"""<html><body style='font-family:sans-serif;text-align:center;padding-top:50px;background:#1a1a2e;color:#fff;'>
            <h2 style='color:#00d992;'>✅ 登录成功！</h2>
            <p>欢迎，<b>{html.escape(str(result['name']))}</b></p>
            <p style='color:#888;font-size:14px;'>可以关闭此页面，返回APP查看状态</p>
            <script>setTimeout(function(){{window.location.href='/'}}, 2000);</script>
            </body></html>"""
        except Exception as e:
            import traceback
            traceback.print_exc()
            return f"<html><body style='font-family:sans-serif;text-align:center;padding-top:50px;'><h2>登录异常</h2><p>{html.escape(str(e))}</p><p>可以关闭此页面返回APP</p></body></html>"

