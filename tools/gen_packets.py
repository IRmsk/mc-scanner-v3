#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
协议包 ID 表自动生成器。
从官方 PrismarineJS/minecraft-data 生成，杜绝手抄错误。
用法:
  python tools/gen_packets.py --data ./minecraft-data --output core/packets_auto.json
  python tools/gen_packets.py --download  # 自动下载 minecraft-data
"""
import argparse
import json
import os
import shutil
import sys
import tempfile
import urllib.request
import zipfile

# 正常 minecraft-data zip 约 10-20MB；超过上限说明下载异常/被投毒，直接中止
_MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
# 生成结果自检门槛：低于此值几乎必定是结构变化或下载损坏，
# 宁可拒绝写盘，也不能用近乎空表覆盖 core/packets_auto.json
_MIN_PROTOCOLS = 8
_MIN_PLAY_SB = 10


def download_minecraft_data(dest_dir: str):
    url = "https://github.com/PrismarineJS/minecraft-data/archive/refs/heads/master.zip"
    print(f"[*] 下载 minecraft-data: {url}")
    zip_path = os.path.join(tempfile.gettempdir(), "minecraft-data.zip")
    # 原实现 urlretrieve 无超时也无大小限制：下载被截断/中间人投毒都会静默继续
    req = urllib.request.Request(url, headers={"User-Agent": "mc-scanner-v3-gen_packets"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(zip_path, "wb") as out:
        total = 0
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_DOWNLOAD_BYTES:
                raise RuntimeError(f"下载超过 {_MAX_DOWNLOAD_BYTES} 字节上限，已中止")
            out.write(chunk)
    print(f"[*] 下载完成 {total} 字节，解压到 {dest_dir}")
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(dest_dir)
    extracted = os.path.join(dest_dir, "minecraft-data-master")
    return extracted if os.path.exists(extracted) else dest_dir


def get_proto_version(data_dir: str, version: str) -> int:
    vpath = os.path.join(data_dir, "data", "pc", version, "version.json")
    if os.path.exists(vpath):
        with open(vpath, 'r', encoding='utf-8') as f:
            return json.load(f).get("version", 0)
    return 0


def extract_packets(protocol_data: dict) -> dict:
    """从 protocol.json 提取各阶段包 ID: {stage: {direction: {name: pid_int}}}"""
    result = {}
    for stage in ["handshaking", "status", "login", "configuration", "play"]:
        stage_data = protocol_data.get(stage)
        if not isinstance(stage_data, dict):
            continue
        result[stage] = {"toServer": {}, "toClient": {}}
        for direction in ["toServer", "toClient"]:
            dir_data = stage_data.get(direction)
            if not isinstance(dir_data, dict):
                continue
            types = dir_data.get("types", {})
            packet_def = types.get("packet")
            if not isinstance(packet_def, list) or len(packet_def) < 2:
                continue
            try:
                fields = packet_def[1]
                if not isinstance(fields, list) or len(fields) == 0:
                    continue
                name_field = fields[0]
                type_info = name_field.get("type", [])
                if isinstance(type_info, list) and len(type_info) > 1:
                    mapper = type_info[1]
                    mappings = mapper.get("mappings", {})
                    for pid_hex, name in mappings.items():
                        try:
                            pid = int(pid_hex, 16) if pid_hex.startswith("0x") else int(pid_hex)
                            result[stage][direction][name] = pid
                        except ValueError:
                            pass
            except Exception:
                continue
    return result


def _validate_tables(proto_to_packets: dict) -> list:
    """生成结果自检，返回问题列表（空列表表示通过）。"""
    problems = []
    if len(proto_to_packets) < _MIN_PROTOCOLS:
        problems.append(f"协议版本数过少: {len(proto_to_packets)} < {_MIN_PROTOCOLS}")
    if not any(p >= 767 for p in proto_to_packets):
        problems.append("缺少 >=767 的高版本协议表")
    for proto, tables in proto_to_packets.items():
        sb = (tables.get("play") or {}).get("toServer") or {}
        cb = (tables.get("play") or {}).get("toClient") or {}
        if len(sb) < _MIN_PLAY_SB or not cb:
            problems.append(f"协议 {proto} 的 play 包异常少: toServer={len(sb)}, toClient={len(cb)}")
    return problems


def generate_auto_tables(data_dir: str, output_path: str):
    versions_dir = os.path.join(data_dir, "data", "pc")
    if not os.path.exists(versions_dir):
        print(f"[!] 找不到版本目录: {versions_dir}")
        return False

    versions = sorted([d for d in os.listdir(versions_dir)
                       if os.path.isdir(os.path.join(versions_dir, d))])
    print(f"[*] 找到 {len(versions)} 个版本")

    # 按协议号去重：同一协议号只保留第一个有 protocol.json 的版本
    proto_to_packets = {}
    for version in versions:
        proto = get_proto_version(data_dir, version)
        if proto == 0 or proto < 340 or proto in proto_to_packets:
            continue
        protocol_path = os.path.join(data_dir, "data", "pc", version, "protocol.json")
        if not os.path.exists(protocol_path):
            continue
        with open(protocol_path, 'r', encoding='utf-8') as f:
            protocol_data = json.load(f)
        packets = extract_packets(protocol_data)
        if packets and packets.get("play", {}).get("toServer"):
            proto_to_packets[proto] = packets
            print(f"  - 协议 {proto} ({version}): play.toServer={len(packets['play']['toServer'])} 包")

    print(f"[*] 共 {len(proto_to_packets)} 个协议版本")

    # 写盘前自检：不合格直接失败退出，绝不用空表覆盖源码
    problems = _validate_tables(proto_to_packets)
    if problems:
        print("[!] 生成结果未通过自检，拒绝写盘:")
        for p in problems:
            print(f"    - {p}")
        return False

    # 纯数据就存纯数据：41 个版本 / 149KB，放 JSON 而不是 .py，
    # 免得解释器每次 import 都去解析几千行字典字面量。
    content = json.dumps(proto_to_packets, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
    print(f"[*] 生成时间: {__import__('datetime').datetime.now().isoformat()}")
    # 先写临时文件并做语法校验，再备份旧文件后原子替换
    tmp_path = output_path + ".tmp"
    with open(tmp_path, 'w', encoding='utf-8') as f:
        f.write(content)
    try:
        json.loads(content)
    except json.JSONDecodeError as e:
        print(f"[!] 生成内容 JSON 校验失败: {e}")
        os.unlink(tmp_path)
        return False
    if os.path.exists(output_path):
        shutil.copy2(output_path, output_path + ".bak")
    os.replace(tmp_path, output_path)
    print(f"[*] 已生成: {output_path}")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", help="minecraft-data 本地路径")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--output", default="core/packets_auto.json")
    args = parser.parse_args()

    data_dir = args.data
    if args.download or not data_dir:
        dest = os.path.abspath(os.path.join(tempfile.gettempdir(), "mcscanner_mcdata"))
        tmp_root = os.path.abspath(tempfile.gettempdir())
        # rmtree 前校验路径确实在临时目录内，避免误删
        if os.path.exists(dest) and os.path.commonpath([dest, tmp_root]) == tmp_root:
            shutil.rmtree(dest)
        data_dir = download_minecraft_data(dest)

    if not data_dir or not os.path.exists(data_dir):
        print("[!] 请提供 --data 路径或使用 --download")
        sys.exit(1)

    success = generate_auto_tables(data_dir, args.output)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
