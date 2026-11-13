# -*- coding: utf-8 -*-
"""微软/Minecraft正版认证模块。
Azure AD v2.0 设备码流程 + RSA/AES加密握手。

===================== 关于 client_id（重要，合规相关） =====================
下面这几个 client_id 都是**别人的应用**，不是本项目的：
    CLIENT_ID        = Azure CLI 的公开 client_id
    FCL_CLIENT_ID    = FCL 启动器的 client_id
    LEGACY_CLIENT_ID = 旧版官方启动器的 client_id
拿它们去发登录请求，等于"以他人应用的身份"完成 OAuth 授权。这可能违反 Microsoft
以及对应项目的使用条款，也随时可能被对方吊销（一旦吊销，本项目的登录功能会整体失效）。

**对外分发前请换成你自己在 Azure 注册的应用**，不需要改代码：
    - 配置文件里设置 msa_client_id / msa_fcl_client_id，或
    - 环境变量 MC_MSA_CLIENT_ID / MC_MSA_FCL_CLIENT_ID
再用你自己的应用替换下面的默认值，然后删掉这段说明。
=========================================================================
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

# 内置默认值（他人应用，仅为兼容保留；请按上面的说明替换为自己的）
CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
SCOPE = "XboxLive.signin offline_access"
FCL_CLIENT_ID = "d903cc0e-c3b4-4a3c-b347-06c2e6269be0"
FCL_REDIRECT_URI = "http://localhost:8090/auth-response"
# 旧版client_id（保留，用于兼容）
LEGACY_CLIENT_ID = "00000000402b5328"
REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf"

_notice_shown = False


def _default_client_notice():
    """第一次真正用到内置 client_id 时提示一次，避免使用者不知情。"""
    global _notice_shown
    if _notice_shown:
        return
    _notice_shown = True
    print("[MSA] 注意: 正在使用内置的第三方 client_id（Azure CLI / FCL）。"
          "对外分发请通过配置 msa_client_id / msa_fcl_client_id 换成你自己的应用。")


def _client_id() -> str:
    """优先级：调用方传入 > 配置/环境变量 > 内置默认值。"""
    try:
        import config
        v = config.get("msa_client_id", "") or ""
    except Exception:
        v = ""
    cid = v or os.environ.get("MC_MSA_CLIENT_ID", "") or CLIENT_ID
    if cid == CLIENT_ID:
        _default_client_notice()
    return cid


def _fcl_client_id() -> str:
    """FCL 流程的 client_id，同样支持配置覆盖。"""
    try:
        import config
        v = config.get("msa_fcl_client_id", "") or ""
    except Exception:
        v = ""
    cid = v or os.environ.get("MC_MSA_FCL_CLIENT_ID", "") or FCL_CLIENT_ID
    if cid == FCL_CLIENT_ID:
        _default_client_notice()
    return cid

def _post(url, data=None, headers=None):
    """简单POST请求，出错时返回错误详情"""
    body = urllib.parse.urlencode(data).encode() if data else b""
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors='replace')
        print(f"[MSA] HTTP {e.code}: {err_body[:300]}")
        return {"error": f"HTTP {e.code}", "error_description": err_body[:500]}
    except Exception as e:
        print(f"[MSA] 请求异常: {e}")
        return {"error": str(e)}


def start_device_code(client_id=None):
    """开始设备码流程(v2.0)，返回 {user_code, verification_uri, device_code, interval}"""
    cid = client_id or _client_id()
    data = {
        "client_id": cid,
        "scope": SCOPE,
    }
    r = _post("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode", data)
    if "error" in r and "user_code" not in r:
        return r
    return {
        "user_code": r["user_code"],
        "verification_uri": r.get("verification_uri", "https://www.microsoft.com/link"),
        "device_code": r["device_code"],
        "interval": r.get("interval", 5),
        "expires_in": r.get("expires_in", 900),
    }


def poll_token(device_code, client_id=None, interval=5):
    """轮询获取MSA access token(v2.0)。用户登录后返回 {access_token, refresh_token}"""
    cid = client_id or _client_id()
    data = {
        "client_id": cid,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
    }
    r = _post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", data)
    return r


def get_auth_url(client_id=None, redirect_uri=None):
    """生成授权URL（隐式流程，直接返回access_token）"""
    cid = client_id or _client_id()
    rd = redirect_uri or REDIRECT_URI
    params = {
        "client_id": cid,
        "response_type": "token",
        "redirect_uri": rd,
        "scope": SCOPE,
    }
    return "https://login.live.com/oauth20_authorize.srf?" + urllib.parse.urlencode(params)


def exchange_code(code, client_id=None, redirect_uri=None):
    """用授权码换MSA access token"""
    cid = client_id or _client_id()
    rd = redirect_uri or REDIRECT_URI
    data = {
        "client_id": cid,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": rd,
        "scope": SCOPE,
    }
    r = _post("https://login.live.com/oauth20_token.srf", data)
    return r


def get_fcl_auth_url():
    """生成FCL授权码流程的登录URL（旧版MSA端点，已验证可用）"""
    params = {
        "client_id": _fcl_client_id(),
        "response_type": "code",
        "redirect_uri": FCL_REDIRECT_URI,
        "scope": SCOPE,
    }
    return "https://login.live.com/oauth20_authorize.srf?" + urllib.parse.urlencode(params)


def fcl_exchange_code(code):
    """用FCL授权码换MSA access token（旧版MSA端点）"""
    data = {
        "client_id": _fcl_client_id(),
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": FCL_REDIRECT_URI,
        "scope": SCOPE,
    }
    r = _post("https://login.live.com/oauth20_token.srf", data)
    return r


def fcl_get_device_code():
    """FCL设备码流程：获取设备码（v2.0端点，FCL同款）"""
    data = {
        "client_id": _fcl_client_id(),
        "scope": SCOPE,
    }
    r = _post("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode", data)
    return r


def fcl_poll_device_code(device_code):
    """FCL设备码流程：轮询获取MSA token（v2.0端点）"""
    data = {
        "client_id": _fcl_client_id(),
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
    }
    r = _post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", data)
    return r


def xbox_auth(msa_token):
    """MSA token → Xbox Live token。v2.0端点用d=前缀（FCL同款）"""
    # v2.0端点返回的token用d=前缀（FCL/Minecraft启动器都这么做）
    rps_ticket = f"d={msa_token}"
    data = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": rps_ticket,
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
    }
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        "https://user.auth.xboxlive.com/user/authenticate",
        data=body, method="POST"
    )
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        r = json.loads(resp.read().decode())
    return r["Token"], r["DisplayClaims"]["xui"][0]["uhs"]


def xsts_auth(xbox_token):
    """Xbox token → XSTS token"""
    data = {
        "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbox_token]},
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT",
    }
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        "https://xsts.auth.xboxlive.com/xsts/authorize",
        data=body, method="POST"
    )
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            r = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        r = json.loads(e.read().decode())
        if r.get("XErr") == 2148916233:
            raise Exception("该微软账号没有Xbox账号，需要先登录一次Xbox") from e
        if r.get("XErr") == 2148916235:
            raise Exception("账号被封禁或需要验证年龄") from e
        raise Exception(f"XSTS认证失败: {r}") from e
    return r["Token"]


def mc_login(uhs, xsts_token):
    """XSTS → Minecraft access token"""
    data = {"identityToken": f"XBL3.0 x={uhs};{xsts_token}"}
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        "https://api.minecraftservices.com/authentication/login_with_xbox",
        data=body, method="POST"
    )
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as resp:
        r = json.loads(resp.read().decode())
    return r["access_token"]


def mc_profile(mc_token):
    """获取MC玩家信息"""
    req = urllib.request.Request(
        "https://api.minecraftservices.com/minecraft/profile"
    )
    req.add_header("Authorization", f"Bearer {mc_token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            r = json.loads(resp.read().decode())
        return {"uuid": r["id"], "name": r["name"]}
    except urllib.error.HTTPError as e:
        raise Exception("该账号未购买Minecraft") from e


def full_login_flow(msa_token):
    """完整流程：MSA token → MC token + profile"""
    xbox_token, uhs = xbox_auth(msa_token)
    xsts_token = xsts_auth(xbox_token)
    mc_token = mc_login(uhs, xsts_token)
    profile = mc_profile(mc_token)
    return {"access_token": mc_token, "uuid": profile["uuid"], "name": profile["name"]}


def join_server(mc_token, uuid, server_id_hash):
    """向Mojang发送joinServer请求（正版加密握手时调用）"""
    data = {
        "accessToken": mc_token,
        "selectedProfile": uuid,
        "serverId": server_id_hash,
    }
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        "https://sessionserver.mojang.com/session/minecraft/join",
        data=body, method="POST"
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {mc_token}")
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        print(f"[正版] joinServer失败: {e}")
        return False


def fetch_certificates(mc_token):
    """从Mojang获取聊天签名用的RSA密钥对（Minecraft 1.19+聊天签名用RSA-2048+SHA256）。
    返回 {privateKey(PEM), publicKey(PEM), publicKeySignature(base64), publicKeySignatureV2(base64), expiresAt} 或 None。
    """
    req = urllib.request.Request(
        "https://api.minecraftservices.com/player/certificates",
        method="POST",
        data=b"{}",
        headers={"Content-Type": "application/json"}
    )
    req.add_header("Authorization", f"Bearer {mc_token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            kp = data["keyPair"]
            return {
                "privateKey": kp["privateKey"],
                "publicKey": kp["publicKey"],
                "publicKeySignature": data.get("publicKeySignature", ""),
                "publicKeySignatureV2": data.get("publicKeySignatureV2", data.get("publicKeySignature", "")),
                "expiresAt": data["expiresAt"],
            }
    except Exception as e:
        print(f"[正版] 获取certificates失败: {e}")
        return None


def refresh_msa_token(refresh_token, client_id=None):
    """用refresh_token刷新MSA access_token。返回 {access_token, refresh_token} 或 None"""
    if not refresh_token:
        return None
    cid = client_id or _fcl_client_id()  # FCL流程
    data = {
        "client_id": cid,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": SCOPE,
    }
    r = _post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", data)
    if r.get("access_token"):
        return {"access_token": r["access_token"], "refresh_token": r.get("refresh_token", refresh_token)}
    print(f"[正版] MSA token刷新失败: {r.get('error', 'unknown')}")
    return None


def refresh_mc_token(refresh_token, client_id=None):
    """完整刷新流程：MSA refresh_token → 新MC token。返回 {access_token, uuid, name, refresh_token} 或 None"""
    msa = refresh_msa_token(refresh_token, client_id)
    if not msa:
        return None
    try:
        result = full_login_flow(msa["access_token"])
        result["refresh_token"] = msa["refresh_token"]
        print(f"[正版] token自动刷新成功: {result.get('name')}")
        return result
    except Exception as e:
        print(f"[正版] MC token刷新失败: {e}")
        return None
