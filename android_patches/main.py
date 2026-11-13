"""MC Scanner Android 入口 - 优化版
显示启动进度，Flask就绪后自动跳转，失败显示错误
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

# 启动状态文件，WebView轮询读取
STATUS_FILE = os.path.join(DATA_DIR, "startup_status.txt")

# 端口可用环境变量覆盖（Android 打包默认 8090；仓库 Web 面板默认 8080）
PORT = int(os.environ.get("MCSCANNER_PORT", "8090"))


def set_status(msg):
    with open(STATUS_FILE, "w", encoding="utf-8") as f:
        f.write(msg)
    print(f"[MC Scanner] {msg}")

def start_flask():
    """后台线程启动Flask"""
    try:
        set_status("正在导入模块...")
        from web.app import app as real_app

        # 仅在显式 debug（MCSCANNER_DEBUG=1）时才把 traceback 回吐给 HTTP 客户端：
        # 默认处理器会暴露绝对路径和内部实现，且覆盖 web/app.py 刻意做的脱敏 500 响应。
        if os.environ.get("MCSCANNER_DEBUG", "") == "1":
            @real_app.errorhandler(500)
            def show_traceback(e):
                import traceback
                tb = traceback.format_exc()
                return f"<h2>500错误</h2><pre style='white-space:pre-wrap;font-size:12px;color:red'>{tb}</pre>", 500

            @real_app.errorhandler(Exception)
            def show_all_errors(e):
                import traceback
                tb = traceback.format_exc()
                return f"<h2>错误</h2><pre style='white-space:pre-wrap;font-size:12px;color:red'>{tb}</pre>", 500

        set_status("正在启动Web服务...")
        real_app.run(host="127.0.0.1", port=PORT, debug=False, use_reloader=False, threaded=True)
    except Exception:
        err = traceback.format_exc()
        set_status(f"启动失败: {err}")
        print(f"[MC Scanner] Flask启动失败: {err}")

if __name__ == "__main__":
    set_status("正在初始化...")

    # 后台启动Flask
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()

    # 等Flask就绪（最多等90秒）
    import urllib.request
    flask_ready = False
    for i in range(180):  # 180 * 0.5 = 90秒
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=1)
            flask_ready = True
            set_status("启动成功！")
            break
        except Exception:
            time.sleep(0.5)

    # 加载WebView
    try:
        from jnius import autoclass
        PythonActivity = autoclass('org.kivy.android.PythonActivity')

        if flask_ready:
            # Flask就绪，直接加载
            PythonActivity.loadUrl(f"http://127.0.0.1:{PORT}")
            set_status("WebView加载中...")
        else:
            # Flask没就绪，加载错误页面显示状态
            with open(STATUS_FILE, "r", encoding="utf-8") as f:
                status = f.read()
            error_html = f"""<html><body style='font-family:sans-serif;padding:20px;background:#1a1a2e;color:#fff;'>
            <h2 style='color:#ff6b6b;'>启动超时</h2>
            <p>Flask服务未能在90秒内启动。</p>
            <h3>启动日志：</h3>
            <pre style='white-space:pre-wrap;background:#000;padding:10px;border-radius:6px;font-size:11px;'>{status}</pre>
            <p style='color:#888;margin-top:20px;'>请尝试：1. 杀掉APP重新打开 2. 检查手机存储空间 3. 联系开发者</p>
            </body></html>"""
            error_file = os.path.join(DATA_DIR, "startup_error.html")
            with open(error_file, "w", encoding="utf-8") as f:
                f.write(error_html)
            PythonActivity.loadUrl(f"file://{error_file}")
    except Exception as e:
        print(f"[MC Scanner] WebView加载失败: {e}")
        traceback.print_exc()

    # 保持主线程运行
    while True:
        time.sleep(1)
