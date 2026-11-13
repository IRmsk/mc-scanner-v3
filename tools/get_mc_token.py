#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minecraft 正版 Token 获取工具（Microsoft 设备码授权）
用法: python3 tools/get_mc_token.py
流程: 设备码 -> 浏览器登录微软账号 -> 获取 access token -> Mojang 验证 -> 保存 token
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

# Minecraft Java 版官方 Azure 应用 ID
CLIENT_ID = "00000000402b5328"
SCOPE = "XboxLive.signin offline_access"


def http_post(url, data, headers=None):
    if headers is None:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def http_post_json(url, data, headers=None):
    if headers is None:
        headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def step1_device_code():
    """步骤1: 获取设备码"""
    print("[1/5] 请求设备码...")
    data = {
        "client_id": CLIENT_ID,
        "scope": SCOPE,
    }
    resp = http_post("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode", data)
    print(f"\n请在浏览器打开: {resp['verification_uri']}")
    print(f"输入验证码: {resp['user_code']}")
    print("\n(页面打开后登录你的微软账号，输入上面的验证码并授权)")
    return resp["device_code"], int(resp["interval"])


def step2_poll_token(device_code, interval, timeout: float = 600):
    """步骤2: 轮询获取 Microsoft access token。

    返回 (access_token, refresh_token, expires_in)。原实现无总超时（不授权就无限轮询），
    且只处理 HTTPError，遇到 URLError / 非 JSON 错误页会直接 traceback。
    """
    print("\n[2/5] 等待浏览器授权...")
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID,
        "device_code": device_code,
    }
    deadline = time.time() + timeout
    while True:
        if time.time() > deadline:
            print("  等待授权超时，请重新运行")
            sys.exit(1)
        time.sleep(interval)
        try:
            resp = http_post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", data)
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode())
            except Exception:
                body = {}
            error = body.get("error", "")
            if error == "authorization_pending":
                print("  等待中... (请在浏览器完成登录)")
                continue
            elif error == "slow_down":
                interval += 2
                continue
            elif error == "expired_token":
                print("  设备码已过期，请重新运行")
                sys.exit(1)
            else:
                print(f"  错误: {error} - {body.get('error_description', '')}")
                sys.exit(1)
        except (urllib.error.URLError, OSError, ValueError) as e:
            # 网络抖动 / 返回的不是 JSON 页，重试而不是抛栈退出
            print(f"  网络错误，稍后重试: {e}")
            continue
        if "access_token" in resp:
            print("  授权成功!")
            # 原实现硬编码 86400，这里采用服务端返回的 expires_in
            return (resp["access_token"], resp.get("refresh_token", ""),
                    int(resp.get("expires_in", 86400)))


def step3_xbox_live(ms_access_token):
    """步骤3: 用 Microsoft token 换 Xbox Live token"""
    print("[3/5] 登录 Xbox Live...")
    data = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": f"d={ms_access_token}",
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
    }
    resp = http_post_json("https://user.auth.xboxlive.com/user/authenticate", data)
    return resp["Token"], resp["DisplayClaims"]["xui"][0]["uhs"]


def step4_xsts(xbl_token):
    """步骤4: 用 Xbox Live token 换 XSTS token"""
    print("[4/5] 获取 XSTS token...")
    data = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbl_token],
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT",
    }
    try:
        resp = http_post_json("https://xsts.auth.xboxlive.com/xsts/authorize", data)
        return resp["Token"], resp["DisplayClaims"]["xui"][0]["uhs"]
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode())
        if body.get("XErr") == 2148916233:
            print("  错误: 该微软账号没有购买 Minecraft Java 版!")
        elif body.get("XErr") == 2148916235:
            print("  错误: 该账号所在地区不支持 Xbox Live")
        else:
            print(f"  XSTS 错误: {body}")
        sys.exit(1)


def step5_minecraft_token(xsts_token, uhs):
    """步骤5: 用 XSTS token 换 Minecraft access token"""
    print("[5/5] 获取 Minecraft access token...")
    data = {"identityToken": f"XBL3.0 x={uhs};{xsts_token}"}
    resp = http_post_json("https://api.minecraftservices.com/authentication/login_with_xbox", data)
    mc_access_token = resp["access_token"]

    # 获取玩家信息
    req = urllib.request.Request(
        "https://api.minecraftservices.com/minecraft/profile",
        headers={"Authorization": f"Bearer {mc_access_token}"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        profile = json.loads(r.read().decode())

    return mc_access_token, profile


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Minecraft 正版 Token 获取工具")
    parser.add_argument("--out", default="minecraft_token.json", help="token 输出文件")
    parser.add_argument("--save-refresh", action="store_true",
                        help="同时保存 refresh_token（默认不落盘：它可长期换取新 access token）")
    parser.add_argument("--timeout", type=float, default=600,
                        help="等待浏览器授权的总秒数（默认 600）")
    args = parser.parse_args()

    print("=" * 60)
    print("Minecraft 正版 Token 获取工具")
    print("=" * 60)
    print()

    device_code, interval = step1_device_code()
    ms_token, refresh_token, expires_in = step2_poll_token(device_code, interval,
                                                           timeout=args.timeout)
    xbl_token, uhs = step3_xbox_live(ms_token)
    xsts_token, uhs = step4_xsts(xbl_token)
    mc_token, profile = step5_minecraft_token(xsts_token, uhs)

    print()
    print("=" * 60)
    print("获取成功!")
    print(f"玩家名: {profile['name']}")
    print(f"UUID: {profile['id']}")
    print(f"Minecraft Access Token: {mc_token[:50]}...")
    print("=" * 60)

    # 保存到文件
    result = {
        "username": profile["name"],
        "uuid": profile["id"],
        "access_token": mc_token,
        "expires_at": int(time.time()) + expires_in,   # 采用服务端返回的有效期
    }
    if args.save_refresh:
        # 默认不落盘：refresh_token 泄漏等于账号长期失守
        result["refresh_token"] = refresh_token
    out_path = args.out
    # 以 0600 直接创建再写入：原实现先 open() 普通权限、之后才 chmod，存在权限窗口
    fd = os.open(out_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    try:
        os.chmod(out_path, 0o600)   # 文件已存在且权限较松时纠正
    except Exception:
        pass
    print(f"\n已保存到: {out_path}")
    print(f"注意: token 有效期约 {expires_in} 秒")
    if not args.save_refresh:
        print("      本次未保存 refresh_token（需要请加 --save-refresh）")
    print("安全提示: 此文件包含敏感凭证，请勿分享或提交到 git")


if __name__ == "__main__":
    main()
