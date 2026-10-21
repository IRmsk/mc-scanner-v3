#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MC Scanner - 综合 Minecraft 服务器扫描器（版本号见 config.__version__）
整合 V1 功能完整性与 V2 架构优势的超越版。

子命令:
  portscan  只扫描端口
  scan      扫描 + SLP 探测 + 认证检测
  masscan   masscan 全网端口发现
  import    导入 masscan 结果
  query     查询 SQLite 数据库
  bot       单独对一台服务器登录发消息
  web       启动 Web 控制面板

用法:
  python cli.py scan 1.2.3.0/24
  python cli.py web --port 8080
"""
import argparse
import json
import os
import sys
import time

_base_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _base_dir)

# 加载 libs/ 依赖，C扩展架构不匹配时自动降级到系统包
_libs_dir = os.path.join(_base_dir, 'libs')
if os.path.isdir(_libs_dir):
    sys.path.insert(0, _libs_dir)
    try:
        import flask  # noqa: F401
        for _pkg in ('Crypto', 'cryptography', 'uvloop', 'simdjson', 'cffi'):
            __import__(_pkg)
    except (ImportError, OSError):
        sys.path.remove(_libs_dir)
        for _mod in list(sys.modules.keys()):
            if _mod.startswith(('Crypto', 'cryptography', 'uvloop', 'simdjson', 'cffi', 'flask')):
                del sys.modules[_mod]

import config
import logger

from scanner.targets import parse_port_spec
from scanner.portscan import get_open_ports
from scanner.masscan import has_masscan
from scanner.engine import ScanEngine
from scanner.random_scan import random_scan, async_random_scan, parse_port_ranges
from core.bot import MCBot


def load_config(path: str = None) -> dict:
    """加载配置（委托给统一config模块，保持向后兼容）"""
    cfg = config.load_config(path)
    if isinstance(cfg.get('ports'), str):
        cfg['ports'] = parse_port_spec(cfg['ports'])
    return cfg


def save_results(results, output_file: str, fmt: str = "json"):
    if not output_file:
        return
    rows = []
    for r in results:
        if isinstance(r, dict):
            rows.append(r)
        elif hasattr(r, '__dataclass_fields__'):
            rows.append({k: getattr(r, k) for k in r.__dataclass_fields__})
        else:
            rows.append({'data': str(r)})
    if fmt == 'csv' or output_file.endswith('.csv'):
        import csv
        if not rows:
            # 原来 rows 为空时也会打印"已保存"，但实际没写文件，误导用户
            logger.warning(f"[!] 无结果，未写入: {output_file}")
            return
        # 各行键可能不一致（不同协议/状态返回的字段有差异），取并集，
        # 否则 DictWriter 遇到首行没有的键会抛 ValueError
        keys = []
        for row in rows:
            for k in row.keys():
                if k not in keys:
                    keys.append(k)
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
            w.writeheader()
            w.writerows(rows)
        logger.info(f"[*] 结果已保存: {output_file} (CSV)")
    else:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(rows, f, ensure_ascii=False, indent=2, default=str)
        logger.info(f"[*] 结果已保存: {output_file} (JSON)")


def _resolve_ports(args, cfg):
    """解析端口参数：--port '25565,25566,1-65535' 或 config ports 列表"""
    from scanner.targets import parse_port_spec
    if getattr(args, 'port', None):
        return parse_port_spec(args.port)
    return cfg.get('ports', [25565])


def _resolve_progress_file(cfg):
    """断点续扫进度文件：读配置项，未配置时才用默认名（原来硬编码忽略配置）"""
    return cfg.get('progress_file') or "scan_progress.json"


def _split_target(spec: str, default_port: int = 25565):
    """解析 host[:port]。缺端口时用 default_port，端口非法抛 ValueError 交由调用方给用法提示。"""
    if ":" in spec:
        host, port = spec.rsplit(":", 1)
        return host, int(port)
    return spec, default_port


def _filtered_targets(args, cfg, ports):
    """异步扫描路径的排除表过滤。

    异步引擎（scan_ports_async / AsyncScanEngine）自身不做 --exclude 过滤，
    所以这里统一走 service.parse_and_filter_targets，避免私网/保留段被静默扫描。
    返回 (targets, exclude_file)。
    """
    from service import parse_and_filter_targets
    exclude_file = getattr(args, 'exclude', None) or cfg.get('exclude_file')
    targets, _ = parse_and_filter_targets(args.targets, ports=ports, exclude_file=exclude_file)
    return targets, exclude_file


def cmd_portscan(args, cfg):
    from service import run_portscan_only
    if args.workers:
        config.set('scan_threads', args.workers)
    if args.timeout:
        config.set('scan_timeout', args.timeout)
    mode = args.mode or cfg.get('scan_mode') or 'balanced'
    # aggressive模式门槛：必须显式--yes确认
    if mode == 'aggressive' and not getattr(args, 'yes', False):
        print("[!] aggressive模式：5000并发、无限速、无随机化，仅适用于内网/信任网络")
        print("[!] 公网使用极易触发IDS封禁和运营商限流。如确认请加 --yes 参数")
        return 2
    if not getattr(args, 'sync_mode', False):
        from scanner.async_portscan import scan_ports_async, get_open_ports_async, has_uvloop
        print(f"[*] 异步端口扫描（uvloop: {'启用' if has_uvloop() else '未安装'}）")
        # 异步路径原来直接用 parse_targets，绕过了排除表；统一走 service 过滤
        targets, _ = _filtered_targets(args, cfg, _resolve_ports(args, cfg))
        if not targets:
            logger.warning("[!] 没有有效目标（可能全部被排除表过滤）")
            return 1
        results = scan_ports_async(
            targets,
            concurrency=args.workers,
            timeout=args.timeout or cfg['scan_timeout'],
            rate_limit=args.rate,
            mode=mode,
            shuffle=not args.no_shuffle,
            batch_cooldown=args.batch_cooldown,
            progress_file=args.resume and _resolve_progress_file(cfg),
        )
        open_ports = get_open_ports_async(results)
        print(f"\n[*] 开放端口 ({len(open_ports)} 个):")
        for ip, port in open_ports:
            print(f"  {ip}:{port}")
        if args.output:
            save_results([{'ip': r.ip, 'port': r.port, 'open': r.is_open,
                           'latency_ms': round(r.latency_ms, 1)} for r in results],
                         args.output, cfg['output_format'])
        # 与 README 退出码表对齐：1 = 无结果
        return 0 if open_ports else 1
    results = run_portscan_only(
        args.targets,
        scan_threads=args.workers,
        scan_timeout=args.timeout or cfg['scan_timeout'],
        rate=args.rate,
        exclude_file=args.exclude or cfg['exclude_file'],
        mode=mode,
        shuffle=not args.no_shuffle,
        batch_cooldown=args.batch_cooldown,
        progress_file=args.resume and _resolve_progress_file(cfg),
        respect_mode=bool(args.mode or cfg.get('scan_mode')),
    )
    open_ports = get_open_ports(results)
    print(f"\n[*] 开放端口 ({len(open_ports)} 个):")
    for ip, port in open_ports:
        print(f"  {ip}:{port}")
    if args.output:
        save_results([{'ip': r.ip, 'port': r.port, 'open': r.is_open,
                       'latency_ms': round(r.latency_ms, 1)} for r in results],
                     args.output, cfg['output_format'])
    # 与 README 退出码表对齐：1 = 无结果
    return 0 if open_ports else 1


def cmd_scan(args, cfg):
    from service import run_full_scan
    if args.workers:
        config.set('scan_threads', args.workers)
    if args.timeout:
        config.set('scan_timeout', args.timeout)
    mode = args.mode or cfg.get('scan_mode') or 'balanced'
    # aggressive模式门槛：必须显式--yes确认
    if mode == 'aggressive' and not getattr(args, 'yes', False):
        print("[!] aggressive模式：5000并发、无限速、无随机化，仅适用于内网/信任网络")
        print("[!] 公网使用极易触发IDS封禁和运营商限流。如确认请加 --yes 参数")
        return 2
    if not getattr(args, 'sync_mode', False):
        from scanner.async_engine import AsyncScanEngine
        from scanner.async_portscan import has_uvloop
        from scanner.async_probe import has_simdjson
        print(f"[*] 异步流水线扫描（uvloop: {'启用' if has_uvloop() else '未安装'}, "
              f"simdjson: {'启用' if has_simdjson() else '未安装'}）")
        # 异步路径原来直接用 parse_targets，绕过 --exclude；统一走 service 过滤
        targets, exclude_file = _filtered_targets(args, cfg, _resolve_ports(args, cfg))
        if not targets:
            logger.warning("[!] 没有有效目标（可能全部被排除表过滤）")
            return 1
        engine_kwargs = dict(
            db_path=args.db or cfg['db_path'],
            concurrency=args.workers,
            # 不再写死 slp_concurrency=400：async_engine 的 safe 降级依赖默认值 200，
            # 写死 400 会让降级条件永假，safe 模式的温和承诺失效
            timeout=args.timeout or cfg['timeout'],
            auth_check=not args.no_auth,
            rate_limit=args.rate,
            fingerprint=getattr(args, 'fingerprint', False),
            mode=mode,
            shuffle=not args.no_shuffle,
            batch_cooldown=args.batch_cooldown,
            progress_file=args.resume and _resolve_progress_file(cfg),
        )
        try:
            # 新版 AsyncScanEngine 支持 exclude_file；旧签名没有该参数，回退即可
            # （无论哪版，targets 都已在上面的 _filtered_targets 里过滤过）
            engine = AsyncScanEngine(exclude_file=exclude_file, **engine_kwargs)
        except TypeError:
            engine = AsyncScanEngine(**engine_kwargs)
        results = engine.scan_with_portscan(targets)
        up_results = [r for r in results if r.get('state') == 'up']
        print(f"\n[*] 发现 {len(up_results)} 个 Minecraft 服务器:")
        for s in sorted(up_results, key=lambda x: x.get('proto', 0)):
            print(f"  {s['ip']}:{s['port']} | {s.get('version','?')}(协议{s.get('proto','?')}) "
                  f"| {s.get('players_online',0)}/{s.get('players_max',0)}人 | {s.get('auth','?')} | {s.get('core_type','?')}")
        if args.output:
            save_results(results, args.output, cfg['output_format'])
        if args.web:
            from web.app import run
            run(args.db or cfg['db_path'], port=args.web)
        return 0 if results else 1
    results = run_full_scan(
        args.targets,
        workers=args.workers,
        timeout=args.timeout or cfg['timeout'],
        auth_check=not args.no_auth,
        rate=args.rate,
        exclude_file=args.exclude or cfg['exclude_file'],
        db_path=args.db or cfg['db_path'],
        fingerprint=getattr(args, 'fingerprint', False),
        mode=mode,
        shuffle=not args.no_shuffle,
        batch_cooldown=args.batch_cooldown,
        progress_file=args.resume and _resolve_progress_file(cfg),
        respect_mode=bool(args.mode or cfg.get('scan_mode')),
    )
    print(f"\n[*] 发现 {len(results)} 个 Minecraft 服务器:")
    for s in sorted(results, key=lambda x: x.get('proto', 0)):
        print(f"  {s['ip']}:{s['port']} | {s.get('version','?')}(协议{s.get('proto','?')}) "
              f"| {s.get('players_online',0)}/{s.get('players_max',0)}人 | {s.get('auth','?')}")
    if args.output:
        save_results(results, args.output, cfg['output_format'])
    if args.web:
        from web.app import run
        run(args.db or cfg['db_path'], port=args.web)
    return 0 if results else 1
def cmd_masscan(args, cfg):
    from service import run_masscan_scan
    import ipaddress
    mode = args.mode or cfg.get('scan_mode') or 'balanced'
    # aggressive 模式门槛：与 cmd_portscan/cmd_scan 对齐，必须显式 --yes 确认
    if mode == 'aggressive' and not getattr(args, 'yes', False):
        print("[!] aggressive模式：5000pps、无限速，仅适用于内网/信任网络")
        print("[!] 公网使用极易触发IDS封禁和运营商限流。如确认请加 --yes 参数")
        return 2
    # 覆盖面守卫：拒绝 /16 及更大网段，除非显式声明授权
    try:
        net = ipaddress.ip_network(args.targets, strict=False)
    except ValueError:
        logger.error(f"无效的目标网段: {args.targets}")
        return 2
    MAX_PREFIXLEN = 16
    if net.prefixlen < MAX_PREFIXLEN and not args.i_have_authorization:
        logger.error(
            f"拒绝执行：{args.targets} 覆盖 {net.num_addresses:,} 个地址，超过安全阈值 /{MAX_PREFIXLEN}。\n"
            f"如果这是你自己持有的网段，请加 --i-have-authorization 并保留授权凭证。"
        )
        return 2
    if not has_masscan():
        logger.warning("[!] masscan 未安装，请先安装: sudo apt install masscan")
        return 1
    result_path = run_masscan_scan(
        targets=args.targets,
        port=args.port or "25565",
        rate=args.rate,
        exclude_file=args.exclude or cfg['exclude_file'],
        output_file=args.output or "scan_results.ndjson",
        auto_import=args.auto_import,
        workers=args.workers or 32,
        auth_check=not args.no_auth,
        db_path=args.db or cfg['db_path'],
        mode=mode,
    )
    logger.info(f"[*] masscan 结果: {result_path}")
    return 0
def cmd_import(args, cfg):
    from service import import_masscan_results
    try:
        results = import_masscan_results(
            args.ndjson,
            workers=args.workers or 32,
            auth_check=not args.no_auth,
            db_path=args.db or cfg['db_path'],
        )
    except FileNotFoundError as e:
        logger.error(f"[!] {e}")
        return 1
    logger.info(f"[*] 导入完成，共 {len(results)} 条记录")
    return 0
def cmd_query(args, cfg):
    from service import query_database, get_db_stats
    db_path = args.db or cfg['db_path']
    if not os.path.exists(db_path):
        logger.error(f"[!] 数据库不存在: {db_path}")
        return 1
    if args.stats:
        s = get_db_stats(db_path)
        print("\n数据库统计:")
        print(f"  总记录: {s['total']}")
        print(f"  有人在线: {s['online_servers']}")
        print("  认证模式分布:")
        for auth, count in s['by_auth'].items():
            print(f"    {auth}: {count}")
        return 0
    rows = query_database(db_path, auth=args.auth, modded=args.modded,
                          search=args.search, limit=args.limit)
    print(f"{len(rows)} 条结果:")
    for r in rows:
        print(f"  {r['ip']}:{r['port']} [{r['auth']}] {r['version']} "
              f"在线 {r['players_online']}/{r['players_max']} · {r['motd'][:40]}")
    # 与 README 退出码表对齐：1 = 无结果
    return 0 if rows else 1


def cmd_bot(args, cfg):
    # 端口解析放进 try：原来 int() 在 try 之外，bot 1.2.3.4:abc 会直接抛 ValueError traceback
    try:
        host, port = _split_target(args.target)
    except ValueError:
        logger.error(f"[!] 目标格式错误: {args.target}（应为 host 或 host:port）")
        return 3
    bot = MCBot(host, port, protocol_version=args.proto,
                username=args.username or cfg['username'], timeout=args.timeout or 15.0)
    try:
        bot.connect()
        print(f"[+] 登录成功 (proto {bot.protocol_version})")
        if args.authme:
            # 等服务器 Play 阶段就绪再登录，避免 /login 被吞（与 bot.py 时序修复一致）
            time.sleep(1.5)
            print(f"[+] AuthMe: {'/register' if args.register else '/login'}")
            bot.authme_login(args.authme, mode="register_then_login" if args.register else "auto")
        if args.message:
            messages = args.message if isinstance(args.message, list) else [args.message]
            for msg in messages:
                bot.send_chat(msg)
                print(f"[+] 已发送: {msg}")
        bot.keep_alive(args.hold or 4.0)
        print("[+] 保持连接结束")
        return 0
    except Exception as e:
        logger.error(f"[!] 失败: {e}")
        return 1
    finally:
        bot.close()


def cmd_web(args, cfg):
    from web.app import run
    run(args.db or cfg['db_path'], port=args.port, host=args.host)


def cmd_random(args, cfg=None):
    """随机IP随机端口暴力扫描"""
    caps = (cfg or {}).get("capabilities", {})
    if not (isinstance(caps, dict) and caps.get("public_scan", False)):
        print("[!] 公网随机扫描能力未启用：请在 config.json 设置 capabilities.public_scan=true")
        print("    （随机扫描目标由随机数决定，无法自证为自有资产，仅用于授权的科研/教学网络）")
        return 4
    port_ranges = parse_port_ranges(args.ports)
    exclude_file = None if args.no_exclude else (args.exclude or "exclude.conf")
    logger.info("[*] 随机暴力扫描模式")
    mode = "异步高速" if not getattr(args, 'sync_mode', False) else "线程池"
    logger.info(f"[*] 目标数: {args.count} | 模式: {mode} | 超时: {args.timeout}s")
    logger.info(f"[*] 端口范围: {args.ports}")
    if exclude_file:
        logger.info(f"[*] 排除列表: {exclude_file}（排除私网/保留段）")
    else:
        logger.info("[*] 不使用排除列表")
    print()

    def progress(done, total, found):
        pct = done / total * 100
        print(f"\r[*] 进度: {done}/{total} ({pct:.1f}%) | 发现: {found} 个开放端口", end="", flush=True)

    import time
    start = time.time()
    if not getattr(args, 'sync_mode', False):
        import asyncio
        from scanner.async_portscan import has_uvloop
        if has_uvloop():
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        open_ports = asyncio.run(async_random_scan(
            target_count=args.count,
            # 尊重用户 --workers：原来 max(args.workers, 500) 会把保守设置强行抬到 500
            concurrency=args.workers,
            timeout=args.timeout,
            port_ranges=port_ranges,
            progress_callback=progress,
            exclude_file=exclude_file,
        ))
    else:
        open_ports = random_scan(
            target_count=args.count,
            max_workers=args.workers,
            timeout=args.timeout,
            port_ranges=port_ranges,
            progress_callback=progress,
            exclude_file=exclude_file,
        )
    elapsed = time.time() - start
    print()
    # elapsed 理论上可能为 0（极快返回），除法前兜底避免 ZeroDivisionError
    logger.info(f"[*] 扫描完成! 耗时: {elapsed:.1f}s ({args.count/max(elapsed, 1e-9):.0f} 目标/秒)")
    logger.info(f"[*] 发现 {len(open_ports)} 个开放端口")
    print()

    if not open_ports:
        logger.warning("[!] 没有发现开放端口，试试增加目标数量或扩大端口范围")
        return 1

    # SLP 探测（并发，不再串行）
    if args.probe:
        logger.info("[*] SLP 探测...")
        engine = ScanEngine(db_path=cfg["db_path"], workers=min(32, args.workers or 200), timeout=3.0)
        results = engine.probe_list(open_ports)
        servers = []
        for i, info in enumerate(results):
            if info.get("state") == "up":
                servers.append({
                    "ip": info["ip"], "port": info["port"],
                    "version": info.get("version"),
                    "players": f"{info.get('players_online', 0)}/{info.get('players_max', 0)}",
                    "motd": str(info.get("motd", ""))[:60],
                })
                print(f"  [{i+1}/{len(results)}] {info['ip']}:{info['port']} | {info.get('version','?')} | {info.get('players_online',0)}/{info.get('players_max',0)}")
        logger.info(f"[*] 发现 {len(servers)} 个 Minecraft 服务器")
        if args.output:
            import json
            # 显式 utf-8：Windows 默认 gbk，写含中文 MOTD 的结果会 UnicodeEncodeError
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(servers, f, indent=2, ensure_ascii=False)
            logger.info(f"[*] 结果已保存到 {args.output}")
    else:
        for ip, port in open_ports:
            print(f"  {ip}:{port}")
        if args.output:
            import json
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump([{"ip": ip, "port": port} for ip, port in open_ports], f, indent=2)
            logger.info(f"[*] 结果已保存到 {args.output}")
    return 0


def cmd_fav(args, cfg):
    """收藏管理：list/add/remove/rescan/tags/import"""
    from storage import favorites
    action = args.action
    # add/remove/tags 必须带 target；rescan 带 target 时也解析。
    # 原来缺 target 会 AttributeError/TypeError，端口非数字会抛 ValueError 堆栈
    parsed = None
    if action in ("add", "remove", "tags") or (action == "rescan" and args.target):
        if not args.target:
            print(f"用法: python cli.py fav {action} <host[:port]>")
            return 3
        try:
            parsed = _split_target(args.target)
        except ValueError:
            print(f"[!] 目标格式错误: {args.target}（应为 host 或 host:port）")
            return 3
    if action == "list":
        tag = getattr(args, 'tag', None)
        search = getattr(args, 'search', None)
        favs = favorites.filter_favorites(tag=tag, search=search)
        if not favs:
            print("暂无收藏")
            return
        print(f"\n收藏列表 ({len(favs)} 个):")
        print(f"{'地址':<22} {'版本':<20} {'核心':<10} {'玩家':<10} {'标签':<20} {'最后检查'}")
        print("-" * 90)
        for f in favs:
            info = f.get("last_info") or {}
            state = info.get("state", "unknown")
            players = f"{info.get('online', 0)}/{info.get('max', 0)}" if state == "up" else state
            tags = ",".join(f.get("tags", []))[:18]
            last = f.get("last_check", "-")[:19] if f.get("last_check") else "-"
            print(f"{f['ip']}:{f['port']:<17} {info.get('version','-'):<20} {info.get('core_type','-'):<10} {players:<10} {tags:<20} {last}")
    elif action == "add":
        ip, port = parsed
        tags = args.tags.split(",") if args.tags else []
        fav = favorites.add_favorite(ip, port, tags=tags, note=args.note or "")
        print(f"[+] 已收藏: {fav['ip']}:{fav['port']}")
    elif action == "remove":
        ip, port = parsed
        ok = favorites.remove_favorite(ip, port)
        print(f"[{'+' if ok else '!'}] {'已移除' if ok else '未找到'}: {ip}:{port}")
    elif action == "rescan":
        if parsed:
            ip, port = parsed
            info = favorites.rescan_one(ip, port, timeout=args.timeout)
            if info and info.get("state") == "up":
                print(f"[+] {ip}:{port} | {info.get('version','?')} | {info.get('online',0)}/{info.get('max',0)}人 | {info.get('core_type','?')}")
            else:
                print(f"[-] {ip}:{port} 离线或不可达")
        else:
            print("[*] 重新探测所有收藏...")
            def _progress(done, total):
                print(f"\r[*] 进度: {done}/{total}", end="", flush=True)
            favs = favorites.rescan_all(timeout=args.timeout, workers=args.workers, progress_callback=_progress)
            print(f"\n[+] 完成，共 {len(favs)} 个收藏")
            up = sum(1 for f in favs if (f.get("last_info") or {}).get("state") == "up")
            print(f"    在线: {up}, 离线: {len(favs) - up}")
    elif action == "tags":
        ip, port = parsed
        tags = args.tags.split(",") if args.tags else []
        fav = favorites.update_tags(ip, port, tags)
        if fav:
            print(f"[+] 标签已更新: {fav['tags']}")
        else:
            print(f"[!] 未找到收藏: {ip}:{port}")
    elif action == "import":
        count = favorites.import_from_file(args.file)
        print(f"[+] 从 {args.file} 导入 {count} 个收藏")
    elif action == "tags-list":
        tags = favorites.get_all_tags()
        print(f"所有标签 ({len(tags)}): {', '.join(tags) if tags else '无'}")


def cmd_rescan(args, cfg):
    """智能重扫管理（v3.3 新增）"""
    from scanner.rescanner import RescanScheduler
    db_path = args.db or cfg["db_path"]
    scheduler = RescanScheduler(db_path, enabled=True)

    if args.list:
        stats = scheduler.stats()
        print("\n重扫队列统计:")
        print(f"  总数: {stats['total']}")
        print(f"  到期待扫: {stats['due_now']}")
        print("  按策略分布:")
        for strategy, count in stats["by_strategy"].items():
            print(f"    {strategy}: {count}")
        all_items = scheduler.get_all(limit=args.limit)
        if all_items:
            print(f"\n前 {len(all_items)} 个重扫计划:")
            for item in all_items:
                next_scan = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(item["next_scan"]))
                print(f"  {item['ip']}:{item['port']} | strategy={item['strategy']} | "
                      f"scan_count={item['scan_count']} | next={next_scan}")
        return

    if args.run:
        due = scheduler.get_due(limit=args.limit)
        if not due:
            print("[*] 没有到期的重扫任务")
            return
        print(f"[*] 执行 {len(due)} 个到期重扫...")
        engine = ScanEngine(db_path=db_path, workers=min(16, cfg["workers"]),
                            timeout=cfg["timeout"], rescan_enabled=True)
        results = []
        for i, item in enumerate(due):
            print(f"\r  [{i+1}/{len(due)}] {item['ip']}:{item['port']}...", end="", flush=True)
            try:
                r = engine.probe_one(item["ip"], item["port"])
                results.append(r)
            except Exception:
                continue
        up = sum(1 for r in results if r.get("state") == "up")
        print(f"\n[+] 重扫完成: {len(results)} 个目标, {up} 个在线")
        return

    if args.clear:
        scheduler.clear()
        print("[*] 重扫队列已清空")
        return

    if args.remove:
        # 缺冒号/端口非数字时给用法提示，不再抛 ValueError
        if ":" not in args.remove:
            print(f"[!] 目标格式错误: {args.remove}（应为 ip:port）")
            return 3
        try:
            ip, port = _split_target(args.remove)
        except ValueError:
            print(f"[!] 目标格式错误: {args.remove}（应为 ip:port）")
            return 3
        scheduler.remove(ip, port)
        print(f"[*] 已移除: {ip}:{port}")
        return 0

    print("用法: python cli.py rescan --list / --run / --clear / --remove ip:port")


def cmd_distributed(args, cfg):
    """分布式任务分片（v3.3 新增）"""
    caps = (cfg or {}).get("capabilities", {})
    if not (isinstance(caps, dict) and caps.get("public_scan", False)):
        print("[!] 分布式扫描能力未启用：请在 config.json 设置 capabilities.public_scan=true")
        print("    （分布式分片用于扩大扫描面，合法自有资产巡检不需要此功能）")
        return 4
    from distributed.shard import ShardManager, shard_cidr

    if args.create:
        shards = shard_cidr(args.create, num_shards=args.shards, ports=cfg["ports"])
        print(f"[*] 已生成 {len(shards)} 个分片:")
        for s in shards:
            print(f"  分片 {s['shard_id']}: {s['targets']} (~{s['estimated_hosts']} 主机)")
        # 保存分片信息
        manager = ShardManager()
        manager.create_job(args.job or "default", args.create, args.shards, cfg["ports"])
        print(f"[*] 任务已保存，使用 'python cli.py distributed --worker <id> --job {args.job or 'default'}' 领取分片")
        return

    if args.worker:
        manager = ShardManager()
        job_id = args.job or "default"
        shard = manager.claim_shard(job_id, args.worker)
        if not shard:
            print("[-] 没有可用分片")
            return
        print(f"[*] Worker {args.worker} 领取分片 {shard['shard_id']}: {shard['targets']}")
        from service import run_full_scan
        results = run_full_scan(shard["targets"], workers=cfg["workers"],
                                 timeout=cfg["timeout"], db_path=args.db or cfg["db_path"])
        manager.complete_shard(job_id, shard["shard_id"], {"found": len(results)})
        print(f"[+] 分片 {shard['shard_id']} 完成: 发现 {len(results)} 台服务器")
        return

    if args.status:
        manager = ShardManager()
        status = manager.get_job_status(args.status)
        if not status:
            print(f"[-] 任务不存在: {args.status}")
            return
        print(f"\n任务 {args.status} 状态:")
        print(f"  总分片: {status['total_shards']}")
        print(f"  已完成: {status['completed_shards']}")
        print(f"  进度: {status['progress']}%")
        for sid, info in status["shards"].items():
            print(f"  分片 {sid}: {info['status']} (worker={info.get('worker') or '-'})")
        return

    print("用法: python cli.py distributed --create CIDR --shards N / --worker ID / --status JOB")


def cmd_proxy(args, cfg):
    """代理管理（v3.3 新增）"""
    from core.proxy import ProxyManager, get_proxy_manager
    proxy_file = args.file or "proxies.txt"
    manager = get_proxy_manager(proxy_file=proxy_file, auto_fetch=False)
    if manager is None:
        if args.fetch:
            # 文件不存在但要fetch，直接创建新管理器
            manager = ProxyManager(proxy_file=proxy_file, auto_fetch=False)
        else:
            print(f"[!] 代理文件不存在: {proxy_file}")
            print("    使用 --fetch 从网络获取代理，或 --add <proto://host:port> 添加")
            return
    if args.fetch:
        count = manager.fetch_from_api(fetch_socks5=args.socks5)
        print(f"[+] 从 ProxyScrape 获取 {count} 个代理")
        return
    if args.check:
        if not args.test_host:
            print("[!] 请通过 --test-host 指定健康检查目标（避免默认向第三方生产服发探测流量）")
            return
        alive = manager.health_check(test_host=args.test_host,
                                      test_port=args.test_port or 25565,
                                      timeout=args.timeout or 5.0)
        print(f"[+] 健康检查完成: {alive}/{len(manager)} 个可用")
        return
    if args.add:
        manager.add_proxy(args.add)
        print(f"[+] 已添加代理: {args.add}")
        return
    # 默认列出代理
    manager.load_from_file()
    print(f"\n代理列表 ({len(manager)} 个):")
    for p in manager.proxies if hasattr(manager, 'proxies') else []:
        print(f"  {p.proto}://{p.host}:{p.port} (失败={p.fail_count})")
    if not manager.proxies:
        print("  (空，使用 --fetch 获取)")


def cmd_rcon(args, cfg):
    """RCON 客户端（v3.3 新增）"""
    from core.rcon import RCONClient, rcon_execute
    caps = cfg.get("capabilities", {})
    if not (isinstance(caps, dict) and caps.get("rcon_commands", False)):
        print("[!] RCON/命令执行能力未启用：请在config中设置 capabilities.rcon_commands=true")
        return 4
    if not args.host:
        print("用法: python cli.py rcon <host:port> -p <password> -c <command>")
        return 3
    if not getattr(args, "yes", False):
        print("[!] 警告：RCON可执行服务器管理命令（op/ban/stop等），仅限授权服务器使用")
        print("[!] 确认执行请加 --yes 参数")
        return 3
    try:
        host, port = _split_target(args.host, default_port=25575)
    except ValueError:
        print(f"[!] 目标格式错误: {args.host}（应为 host 或 host:port）")
        return 3
    # 密码优先取环境变量，避免 -p 明文进入 ps / shell history；空密码直接拒绝
    password = args.password or os.environ.get("MC_RCON_PASSWORD") or ""
    if not password:
        print("[!] RCON 密码为空：请用 -p 传入，或设置环境变量 MC_RCON_PASSWORD")
        return 3
    if args.command:
        result = rcon_execute(host, port, password, args.command, timeout=args.timeout or 10.0)
        print(f"[RCON] {host}:{port}")
        print(f"命令: {args.command}")
        print(f"响应:\n{result}")
        return
    if args.commands_file:
        try:
            with open(args.commands_file, 'r', encoding='utf-8') as f:
                commands = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[!] 文件不存在: {args.commands_file}")
            return
        client = RCONClient(host, port, password, timeout=args.timeout or 10.0)
        if not client.connect():
            print("[!] RCON 连接失败或认证失败")
            return
        results = client.execute_many(commands, delay=args.delay or 0.3)
        client.close()
        print(f"[RCON] 执行 {len(results)} 条命令:")
        for cmd, resp in results.items():
            print(f"  > {cmd}")
            print(f"    {resp[:200]}")
        return
    print("用法: python cli.py rcon <host:port> -p <password> -c <命令>")
    print("  或: python cli.py rcon <host:port> -p <password> -f <命令文件>")


def cmd_commands(args, cfg):
    """登录后自动执行命令（v3.3 新增）"""
    from core.command_runner import run_commands_on_server, CommandScript
    caps = cfg.get("capabilities", {})
    if not (isinstance(caps, dict) and caps.get("rcon_commands", False)):
        print("[!] RCON/命令执行能力未启用：请在config中设置 capabilities.rcon_commands=true")
        return 4
    if not args.target:
        print("用法: python cli.py commands <host:port> -u <用户名> [选项]")
        return 3
    if not getattr(args, "yes", False):
        print("[!] 警告：命令执行可对服务器运行任意指令，仅限授权服务器使用")
        print("[!] 确认执行请加 --yes 参数")
        return 3
    try:
        host, port = _split_target(args.target)
    except ValueError:
        print(f"[!] 目标格式错误: {args.target}（应为 host 或 host:port）")
        return 3
    username = args.username or "CommandBot"
    if args.script:
        script = CommandScript.from_file(args.script, delay=args.delay or 1.0)
    elif args.commands:
        script = CommandScript(delay=args.delay or 1.0)
        for cmd in args.commands.split(';'):
            script.add(cmd.strip())
    else:
        # 默认 info 脚本
        script = CommandScript(delay=args.delay or 1.0)
        script.add("/plugins")
        script.add("/version")
        script.add("/help")
    print(f"[*] 登录 {host}:{port} 作为 {username}，执行 {len(script.commands)} 条命令...")
    try:
        results = run_commands_on_server(host, port, username, script.commands,
                                          timeout=args.timeout or 15.0,
                                          authme_password=args.authme)
        print("\n[+] 执行完成:")
        for r in results:
            status = "✅" if r.success else "❌"
            print(f"  {status} {r.command}")
            if r.response:
                print(f"     {r.response[:150]}")
    except Exception as e:
        print(f"[!] 执行失败: {e}")


def main():
    parser = argparse.ArgumentParser(
        description=f"MC Scanner v{config.__version__} - 综合 Minecraft 服务器扫描器")
    parser.add_argument("--version", action="version",
                        version=f"MC Scanner v{config.__version__}")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument("--db", help="数据库路径")
    sub = parser.add_subparsers(dest="cmd")

    # portscan
    p = sub.add_parser("portscan", help="只扫描端口")
    p.add_argument("targets")
    p.add_argument("--workers", type=int)
    p.add_argument("--timeout", type=float)
    p.add_argument("--rate", type=int, default=None)
    p.add_argument("--port", default=None,
                   help="端口范围，如 '25565' / '25565,25566' / '1-65535'（默认取配置 ports）")
    p.add_argument("--exclude")
    p.add_argument("-o", "--output")
    p.add_argument("--mode", choices=["safe", "balanced", "aggressive"],
                   help="扫描模式: safe=安全低速 / balanced=平衡(默认) / aggressive=高速仅内网")
    p.add_argument("--no-shuffle", action="store_true", help="关闭端口顺序随机化")
    p.add_argument("--batch-cooldown", type=float, help="批间冷却秒数(防突发)")
    p.add_argument("--resume", action="store_true", help="断点续扫(中断后从上次继续)")
    p.add_argument("--sync", dest="sync_mode", action="store_true",
                   help="使用同步线程引擎（默认异步，更快）")
    p.add_argument("--yes", action="store_true", help="确认aggressive模式（高并发无保护，仅内网使用）")
    p.set_defaults(func=cmd_portscan)

    # scan
    s = sub.add_parser("scan", help="扫描 + SLP探测 + 认证检测")
    s.add_argument("targets")
    s.add_argument("--workers", type=int)
    s.add_argument("--timeout", type=float)
    s.add_argument("--no-auth", action="store_true")
    s.add_argument("--fingerprint", action="store_true", help="启用主动协议指纹（每台up服额外1次TCP连接）")
    s.add_argument("--rate", type=int, default=None)
    s.add_argument("--port", default=None,
                   help="端口范围，如 '25565' / '25565,25566' / '1-65535'（默认取配置 ports）")
    s.add_argument("--exclude")
    s.add_argument("-o", "--output")
    s.add_argument("--web", type=int, default=0, help="扫描后启动Web面板端口")
    s.add_argument("--mode", choices=["safe", "balanced", "aggressive"],
                   help="扫描模式: safe=安全低速 / balanced=平衡(默认) / aggressive=高速仅内网")
    s.add_argument("--no-shuffle", action="store_true", help="关闭端口顺序随机化")
    s.add_argument("--batch-cooldown", type=float, help="批间冷却秒数(防突发)")
    s.add_argument("--resume", action="store_true", help="断点续扫(中断后从上次继续)")
    s.add_argument("--sync", dest="sync_mode", action="store_true",
                   help="使用同步线程引擎（默认异步流水线，更快）")
    s.add_argument("--yes", action="store_true", help="确认aggressive模式（高并发无保护，仅内网使用）")
    s.set_defaults(func=cmd_scan)


    # masscan
    m = sub.add_parser("masscan", help="masscan 全网端口发现")
    m.add_argument("--targets", required=True,
                   help="目标 CIDR，如 203.0.113.0/24。必须显式指定。")
    m.add_argument("--rate", type=int, default=None)
    m.add_argument("--port", default="25565")
    m.add_argument("--output", default="scan_results.ndjson")
    m.add_argument("--exclude")
    m.add_argument("--auto-import", action="store_true")
    m.add_argument("--workers", type=int, default=16)
    m.add_argument("--no-auth", action="store_true")
    m.add_argument("--mode", choices=["safe", "balanced", "aggressive"],
                   help="扫描模式: safe=100pps / balanced=1000pps(默认) / aggressive=5000pps仅内网")
    m.add_argument("--yes", action="store_true", help="确认aggressive模式（高吞吐无保护，仅内网使用）")
    m.add_argument("--i-have-authorization", action="store_true",
                   help="确认你对目标网段拥有授权（扫描 /16 及更大网段必须加此参数）")
    m.set_defaults(func=cmd_masscan)

    # import
    i = sub.add_parser("import", help="导入 masscan 结果")
    i.add_argument("ndjson")
    i.add_argument("--workers", type=int, default=16)
    i.add_argument("--no-auth", action="store_true")
    # 原 --timeout / --rate 解析后从未传给 import_masscan_results（死参数），已移除
    i.set_defaults(func=cmd_import)

    # query
    q = sub.add_parser("query", help="查询数据库")
    q.add_argument("--auth")
    q.add_argument("--modded", type=int)
    q.add_argument("--search")
    q.add_argument("--limit", type=int, default=50)
    q.add_argument("--stats", action="store_true")
    q.set_defaults(func=cmd_query)

    # bot
    b = sub.add_parser("bot", help="单独对一台服务器登录发消息")
    b.add_argument("target", help="host:port")
    b.add_argument("--proto", type=int, default=None)
    b.add_argument("-u", "--username")
    b.add_argument("-m", "--message", action="append", help="警告消息（可多次）")
    b.add_argument("--authme")
    b.add_argument("--register", action="store_true")
    b.add_argument("--timeout", type=float, default=15.0)
    b.add_argument("--hold", type=float, default=4.0)
    b.set_defaults(func=cmd_bot)

    # web
    web = sub.add_parser("web", help="启动 Web 控制面板")
    web.add_argument("--port", type=int, default=8080)
    web.add_argument("--host", default="127.0.0.1")
    web.set_defaults(func=cmd_web)

    rnd = sub.add_parser("random", help="随机IP随机端口暴力扫描")
    rnd.add_argument("-n", "--count", type=int, default=1000, help="随机目标数量 (默认: 1000)")
    rnd.add_argument("-p", "--ports", default="25565-25575", help="端口范围 (默认: 25565-25575)")
    rnd.add_argument("-w", "--workers", type=int, default=50, help="线程数 (默认: 50)")
    rnd.add_argument("-t", "--timeout", type=float, default=3.0, help="超时秒数 (默认: 3.0)")
    rnd.add_argument("--probe", action="store_true", help="扫描后自动SLP探测")
    rnd.add_argument("--sync", dest="sync_mode", action="store_true", help="使用同步线程模式（默认异步高速）")
    rnd.add_argument("--exclude", default="exclude.conf", help="排除列表文件（默认: exclude.conf）")
    rnd.add_argument("--no-exclude", action="store_true", help="不使用排除列表")
    rnd.add_argument("-o", "--output", help="结果输出文件")
    rnd.set_defaults(func=cmd_random)
    # fav - 收藏管理
    fav = sub.add_parser("fav", help="收藏管理（list/add/remove/rescan/tags/import）")
    fav.add_argument("action", choices=["list", "add", "remove", "rescan", "tags", "import", "tags-list"],
                     help="操作: list=列表, add=添加, remove=移除, rescan=重查, tags=设置标签, import=导入, tags-list=所有标签")
    fav.add_argument("target", nargs="?", help="目标 host:port（add/remove/rescan/tags 需要）")
    fav.add_argument("--tags", help="标签，逗号分隔（add/tags）")
    fav.add_argument("--note", help="备注（add）")
    fav.add_argument("--tag", help="按标签筛选（list）")
    fav.add_argument("--search", help="关键词搜索（list）")
    fav.add_argument("--file", help="导入文件路径（import），每行 ip:port")
    fav.add_argument("--timeout", type=float, default=5.0, help="重查超时秒数（rescan）")
    fav.add_argument("--workers", type=int, default=10, help="重查并发数（rescan全部）")
    fav.set_defaults(func=cmd_fav)
    # rescan - 智能重扫管理（v3.3 新增）
    rs = sub.add_parser("rescan", help="智能重扫管理（v3.3新增）")
    rs.add_argument("--list", action="store_true", help="列出重扫队列")
    rs.add_argument("--run", action="store_true", help="执行到期重扫")
    rs.add_argument("--clear", action="store_true", help="清空重扫队列")
    rs.add_argument("--remove", help="移除指定目标 (ip:port)")
    rs.add_argument("--limit", type=int, default=50, help="限制数量")
    rs.add_argument("--db", help="数据库路径")
    rs.set_defaults(func=cmd_rescan)
    # distributed - 分布式任务分片（v3.3 新增）
    dist = sub.add_parser("distributed", help="分布式任务分片（v3.3新增）")
    dist.add_argument("--create", help="创建分片 (CIDR)")
    dist.add_argument("--shards", type=int, default=4, help="分片数量")
    dist.add_argument("--worker", help="Worker ID（领取并执行分片）")
    dist.add_argument("--job", help="任务 ID")
    dist.add_argument("--status", help="查看任务状态")
    dist.add_argument("--db", help="数据库路径")
    dist.set_defaults(func=cmd_distributed)

    # proxy - 代理管理（v3.3 新增）
    px = sub.add_parser("proxy", help="代理管理（获取/测试/列出）")
    px.add_argument("--fetch", action="store_true", help="从 ProxyScrape 获取代理")
    px.add_argument("--socks5", action="store_true", help="同时获取 SOCKS5 代理")
    px.add_argument("--check", action="store_true", help="健康检查所有代理")
    px.add_argument("--add", help="添加代理 (host:port 或 socks5://host:port)")
    px.add_argument("--file", help="代理文件路径")
    px.add_argument("--test-host", help="健康检查测试主机")
    px.add_argument("--test-port", type=int, help="健康检查测试端口")
    px.add_argument("--timeout", type=float, help="超时秒数")
    px.set_defaults(func=cmd_proxy)
    # rcon - RCON 客户端（v3.3 新增）
    rc = sub.add_parser("rcon", help="RCON 连接和命令执行")
    rc.add_argument("host", nargs="?", help="主机:端口")
    rc.add_argument("-p", "--password",
                    help="RCON 密码（明文传参会进 shell history/ps，建议用环境变量 MC_RCON_PASSWORD）")
    rc.add_argument("-c", "--command", help="执行单条命令")
    rc.add_argument("-f", "--commands-file", help="从文件加载命令列表")
    rc.add_argument("--delay", type=float, help="命令间延迟(秒)")
    rc.add_argument("--timeout", type=float, help="超时秒数")
    rc.add_argument("--yes", action="store_true", help="确认执行高风险操作")
    rc.set_defaults(func=cmd_rcon)
    # commands - 登录后自动执行命令（v3.3 新增）
    cm = sub.add_parser("commands", help="登录服务器后自动执行命令列表")
    cm.add_argument("target", nargs="?", help="主机:端口")
    cm.add_argument("-u", "--username", help="机器人用户名")
    cm.add_argument("-c", "--commands", help="命令列表，分号分隔")
    cm.add_argument("-s", "--script", help="命令脚本文件")
    cm.add_argument("--delay", type=float, help="命令间延迟(秒)")
    cm.add_argument("--timeout", type=float, help="超时秒数")
    cm.add_argument("--authme", help="AuthMe 密码")
    cm.add_argument("--yes", action="store_true", help="确认执行高风险操作")
    cm.set_defaults(func=cmd_commands)

    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        return 1

    cfg = load_config(args.config if hasattr(args, 'config') else None)
    logger.setup_logger(cfg.get('log_level', 'INFO'))
    # 初始化全局代理（如果proxies.txt存在且有代理，自动启用轮换）
    try:
        import os
        from core.proxy import get_proxy_manager
        from core.conn import set_global_proxy_manager
        proxy_file = cfg.get("proxy_file", "proxies.txt")
        if os.path.exists(proxy_file):
            mgr = get_proxy_manager(proxy_file=proxy_file, auto_fetch=False)
            if mgr and mgr.proxies:
                set_global_proxy_manager(mgr)
                print(f"[*] 已启用代理: {len(mgr.proxies)} 个代理，自动轮换")
    except Exception as e:
        print(f"[!] 代理初始化失败: {e}")
    return args.func(args, cfg)


if __name__ == "__main__":
    sys.exit(main() or 0)
