# -*- coding: utf-8 -*-
"""运行时注入 UI 增强样式、移动端底栏、人格卡片选择。"""
import gzip
import hashlib
import os

from flask import Response, send_from_directory

_PERSONA_JS = r"""
<script>
(function(){
  // 人格 label/name/preview 可经 API 自定义，拼 innerHTML 前必须转义（防存储型 XSS）
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
    });
  }
  function upgradePersonaUI(personas) {
    const sel = document.getElementById('aiBotPersonaSelect');
    if (sel && personas && personas.length) {
      const cur = sel.value;
      sel.innerHTML = '<option value="">选择预设人格...</option>' +
        personas.map(function(p,i){return '<option value="'+i+'">'+esc(p.label||p.name)+'</option>';}).join('');
      if (cur) sel.value = cur;
    }
    // 必须复用主页面已有的 #personaCheckboxes：startMultiAi / toggleAllPersonas /
    // updatePersonaCount 只读这个容器，另建容器会让用户看得见的多选完全失效（静默回落到随机人格）
    var host = document.getElementById('personaCheckboxes');
    if (!host) {
      var multiCount = document.getElementById('multiCount');
      if (!multiCount) return;
      host = document.createElement('div');
      host.id = 'personaCheckboxes';
      var row = multiCount.closest('.form-row') || multiCount.parentElement;
      if (row && row.parentElement) row.parentElement.insertBefore(host, row.nextSibling);
      else return;
      var tip = document.createElement('p');
      tip.className = 'hint';
      tip.textContent = '点选参与互聊的人格（可多选，不选则随机）';
      host.parentElement.insertBefore(tip, host);
    }
    // 容器原本带内联 flex 样式，这里切成卡片网格的样式（同一容器，两套渲染都写它）
    host.className = 'persona-grid';
    host.style.display = '';
    if (!personas || !personas.length) return;
    host.innerHTML = personas.map(function(p,i){
      var label = esc(p.label || p.name || ('人格'+(i+1)));
      var prev = esc((p.preview || p.persona || '').slice(0, 42));
      return '<label class="persona-card" data-idx="'+i+'">' +
        '<input type="checkbox" class="persona-cb" value="'+i+'">' +
        '<div class="pc-label">'+label+'</div>' +
        '<div class="pc-name">'+esc(p.name||'')+'</div>' +
        '<div class="pc-preview">'+prev+'</div></label>';
    }).join('');
    host.querySelectorAll('.persona-card').forEach(function(card){
      card.addEventListener('click', function(e){
        if (e.target.tagName === 'INPUT') return;
        var cb = card.querySelector('input');
        cb.checked = !cb.checked;
        card.classList.toggle('active', cb.checked);
      });
      var cb = card.querySelector('input');
      cb.addEventListener('change', function(){ card.classList.toggle('active', cb.checked); });
    });
  }
  function fetchPersonas() {
    fetch('/api/ai_multi/personas').then(function(r){return r.json();}).then(function(d){
      if (d && d.personas) upgradePersonaUI(d.personas);
    }).catch(function(){});
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fetchPersonas);
  else fetchPersonas();
  document.querySelectorAll('.tab[data-tab="aibot"]').forEach(function(t){
    t.addEventListener('click', function(){ setTimeout(fetchPersonas, 50); });
  });
})();
</script>
"""

_NAV = r"""
<nav class="m-bottom-nav" id="mobileBottomNav" aria-label="主导航">
  <button type="button" data-tab="scan" onclick="switchTab('scan')"><span>◈</span>扫描</button>
  <button type="button" data-tab="results" onclick="switchTab('results')"><span>☰</span>结果</button>
  <button type="button" data-tab="observer" onclick="switchTab('observer')"><span>◎</span>观察</button>
  <button type="button" data-tab="aibot" onclick="switchTab('aibot')"><span>✦</span>AI</button>
  <button type="button" data-tab="settings" onclick="switchTab('settings')"><span>⚙</span>设置</button>
</nav>
<script>
(function(){
  const syncMobNav = (name) => {
    document.querySelectorAll('#mobileBottomNav button').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-tab') === name);
    });
  };
  const wrap = () => {
    const _orig = window.switchTab;
    if (typeof _orig !== 'function' || _orig._mobWrapped) return;
    window.switchTab = function(name) {
      const r = _orig.apply(this, arguments);
      try { syncMobNav(name); } catch (e) {}
      return r;
    };
    window.switchTab._mobWrapped = true;
  };
  setTimeout(wrap, 0);
  setTimeout(wrap, 400);
})();
</script>
"""


# serve_index 每次请求都要读 260KB 的 index.html 并做多次全文替换，这里缓存预处理结果；
# 缓存键只跟文件修改时间走：页面不再注入 web_token（见下方说明）
_index_cache = {"key": None, "html": None, "gzip_body": None, "etag": None}


def _make_response(body: str, etag: str):
    """统一出站：ETag 协商 + gzip。

    index.html 是 276KB 单文件，原来每次刷新全量裸传、无缓存协商、无压缩；
    Flask 不会自动压缩 Response(...) 构造出来的对象，也不给它加 ETag。
    """
    from flask import request as _req

    inm = _req.headers.get("If-None-Match", "") or ""
    if etag and etag in [t.strip() for t in inm.split(",") if t.strip()]:
        resp = Response(status=304)
        resp.headers["ETag"] = etag
        resp.headers["Cache-Control"] = "no-cache"
        return resp

    accepts_gzip = "gzip" in (_req.headers.get("Accept-Encoding", "") or "").lower()
    if accepts_gzip and len(body) > 1024:
        payload = _index_cache.get("gzip_body")
        if payload is None:
            payload = gzip.compress(body.encode("utf-8"), 6)
            _index_cache["gzip_body"] = payload
        resp = Response(payload, mimetype="text/html; charset=utf-8")
        resp.headers["Content-Encoding"] = "gzip"
        resp.headers["Vary"] = "Accept-Encoding"
    else:
        resp = Response(body, mimetype="text/html; charset=utf-8")

    resp.headers["ETag"] = etag
    # no-cache 不是不缓存：允许本地留存，但每次必须带 If-None-Match 回来验证
    resp.headers["Cache-Control"] = "no-cache"
    return resp


def serve_index(web_dir: str):
    html_path = os.path.join(web_dir, "index.html")
    polish_path = os.path.join(web_dir, "ui-polish.css")
    try:
        html_mtime = os.path.getmtime(html_path)
    except OSError:
        return send_from_directory(web_dir, "index.html")
    polish_mtime = os.path.getmtime(polish_path) if os.path.isfile(polish_path) else 0

    # 不再把 web_token 注入页面。原设计想省掉手动登录，但页面壳是免鉴权的：
    # 一旦绑定 0.0.0.0，任何人 GET / 就能从 HTML 里读到固定 token 并接管面板。
    # 固定 token 只走 X-API-Token 头给脚本用，浏览器侧一律走登录会话。
    cache_key = (html_mtime, polish_mtime)
    etag = '"%s"' % hashlib.sha256(repr(cache_key).encode("utf-8")).hexdigest()[:32]
    if _index_cache["key"] == cache_key and _index_cache["html"] is not None:
        return _make_response(_index_cache["html"], etag)

    try:
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
    except OSError:
        return send_from_directory(web_dir, "index.html")

    # 只按标记注释判断，原来额外的 "persona-grid" not in html 会让匹配到该词就整体跳过注入
    if os.path.isfile(polish_path) and "UI polish v3.4.1" not in html:
        try:
            with open(polish_path, "r", encoding="utf-8") as f:
                polish_css = f.read()
            if "</style>" in html:
                html = html.replace("</style>", polish_css + "\n</style>", 1)
        except OSError:
            pass

    # 页面自带 #mobileNav（CSS 已在移动端显示），再注入一份会出现两条叠加底栏
    if 'id="mobileBottomNav"' not in html and 'id="mobileNav"' not in html:
        if "</body>" in html:
            html = html.replace("</body>", _NAV + "</body>", 1)
        elif "</html>" in html:
            html = html.replace("</html>", _NAV + "</html>", 1)

    if "upgradePersonaUI" not in html:
        if "</html>" in html:
            html = html.replace("</html>", _PERSONA_JS + "\n</html>", 1)

    _index_cache["key"] = cache_key
    _index_cache["html"] = html
    _index_cache["gzip_body"] = None      # 内容变了，压缩结果一并失效
    _index_cache["etag"] = etag
    return _make_response(html, etag)
