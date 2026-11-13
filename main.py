"""MC Scanner Android 入口 - 诊断版
分两步：先起最简Flask确认环境，再加载真正的app
"""
import os
import sys
import threading
import time
import traceback

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)

DATA_DIR = os.path.join(os.environ.get("MCSCANNER_DATA", APP_DIR), "data")
os.makedirs(DATA_DIR, exist_ok=True)
os.chdir(DATA_DIR)
os.environ["MCSCANNER_DB_PATH"] = os.path.join(DATA_DIR, "mcscanner.db")

ERROR_FILE = os.path.join(DATA_DIR, "startup_error.html")

# 端口可用环境变量覆盖（Android 打包默认 8090；仓库 Web 面板默认 8080）
PORT = int(os.environ.get("MCSCANNER_PORT", "8090"))


def write_error(msg):
    """把启动错误写到HTML文件"""
    with open(ERROR_FILE, "w", encoding="utf-8") as f:
        f.write("<html><body style='font-family:monospace;padding:20px'>")
        f.write(f"<h2>Flask启动失败</h2><pre style='white-space:pre-wrap;color:red'>{msg}</pre>")
        f.write("</body></html>")

def start_flask():
    from flask import Flask
    app = Flask(__name__)
    error_msg = {"msg": ""}

    @app.route("/")
    def index():
        import os
        cwd = os.getcwd()
        files = os.listdir(cwd)[:20]
        web_dir = os.path.join(cwd, "web")
        web_files = os.listdir(web_dir)[:20] if os.path.isdir(web_dir) else ["NO web dir"]
        info = "<h2>MC Scanner 诊断</h2>"
        info += f"<p>cwd: {cwd}</p>"
        info += f"<p>cwd files: {files}</p>"
        info += f"<p>web files: {web_files}</p>"
        if error_msg["msg"]:
            info += f"<pre style='white-space:pre-wrap;color:red'>{error_msg['msg']}</pre>"
        return info

    try:
        from web.app import app as real_app
        # 仅在显式 debug（MCSCANNER_DEBUG=1）时才把 traceback 回吐给 HTTP 客户端：
        # 默认处理器会暴露绝对路径和内部实现，且覆盖 web/app.py 刻意做的脱敏 500 响应。
        if os.environ.get("MCSCANNER_DEBUG", "") == "1":
            @real_app.errorhandler(500)
            def show_traceback(e):
                import traceback
                tb = traceback.format_exc()
                return f"<h2>500错误详情</h2><pre style='white-space:pre-wrap;font-size:12px;color:red'>{tb}</pre>", 500
            @real_app.errorhandler(Exception)
            def show_all_errors(e):
                import traceback
                tb = traceback.format_exc()
                return f"<h2>错误详情</h2><pre style='white-space:pre-wrap;font-size:12px;color:red'>{tb}</pre>", 500
        real_app.run(host="127.0.0.1", port=PORT, debug=False, use_reloader=False, threaded=True)
    except Exception:
        err = traceback.format_exc()
        print(f"[MC Scanner] app加载失败: {err}")
        error_msg["msg"] = err
        # write_error 原来定义了却从未调用，这里用它落盘一份启动错误页
        write_error(err)
        app.run(host="127.0.0.1", port=PORT, debug=False, use_reloader=False, threaded=True)

if __name__ == "__main__":
    print("[MC Scanner] 正在启动...")

    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()

    # 等Flask就绪
    import urllib.request
    for i in range(30):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=1)
            print("[MC Scanner] Flask就绪")
            break
        except Exception:
            time.sleep(0.5)

    # 加载WebView
    try:
        from jnius import PythonJavaClass, autoclass, java_method
        PythonActivity = autoclass('org.kivy.android.PythonActivity')

        # 自定义WebViewClient，拦截MSA登录redirect
        class MSAWebViewClient(PythonJavaClass):
            __javaclass__ = 'android/webkit/WebViewClient'
            __javacontext__ = 'app'

            @java_method('()V')
            def __init__(self):
                pass

            @java_method('(Landroid/webkit/WebView;Ljava/lang/String;)Z')
            def shouldOverrideUrlLoading(self, view, url):
                print(f"[MSA] shouldOverrideUrlLoading: {url[:100]}")
                # 要求 https 且是微软回调，否则子串匹配可被任意页面伪造
                if url.startswith('https://') and 'oauth20_desktop.srf' in url and 'code=' in url:
                    try:
                        code = url.split('code=')[1].split('&')[0]
                        print(f"[MSA] 捕获到code 长度={len(code)}")
                        import urllib.parse
                        import urllib.request
                        data = urllib.parse.urlencode({'code': code}).encode()
                        req = urllib.request.Request(f'http://127.0.0.1:{PORT}/api/msa/exchange', data=data, method='POST')
                        with urllib.request.urlopen(req, timeout=15) as resp:
                            result = resp.read().decode()
                        print(f"[MSA] exchange结果: {result[:100]}")
                        view.loadUrl(f'http://127.0.0.1:{PORT}')
                    except Exception as e:
                        print(f"[MSA] 交换token失败: {e}")
                        import traceback
                        traceback.print_exc()
                    return True
                return False

            @java_method('(Landroid/webkit/WebView;Ljava/lang/String;)V')
            def onPageFinished(self, view, url):
                print(f"[MSA] onPageFinished: {url[:100]}")
                # 要求 https 且是微软回调，否则子串匹配可被任意页面伪造
                if url.startswith('https://') and 'oauth20_desktop.srf' in url and 'code=' in url:
                    try:
                        code = url.split('code=')[1].split('&')[0]
                        print(f"[MSA] onPageFinished捕获code 长度={len(code)}")
                        import urllib.parse
                        import urllib.request
                        data = urllib.parse.urlencode({'code': code}).encode()
                        req = urllib.request.Request(f'http://127.0.0.1:{PORT}/api/msa/exchange', data=data, method='POST')
                        with urllib.request.urlopen(req, timeout=15) as resp:
                            result = resp.read().decode()
                        print(f"[MSA] exchange结果: {result[:100]}")
                        view.loadUrl(f'http://127.0.0.1:{PORT}')
                    except Exception as e:
                        print(f"[MSA] 交换token失败: {e}")
                        import traceback
                        traceback.print_exc()

        # 设置自定义WebViewClient
        webview = PythonActivity.mWebView
        if webview:
            webview.setWebViewClient(MSAWebViewClient())
            print("[MC Scanner] MSA WebViewClient已设置")

        PythonActivity.loadUrl(f"http://127.0.0.1:{PORT}")
        print("[MC Scanner] WebView已加载")
    except Exception as e:
        print(f"[MC Scanner] WebView加载失败: {e}")
        traceback.print_exc()

    while True:
        time.sleep(1)
