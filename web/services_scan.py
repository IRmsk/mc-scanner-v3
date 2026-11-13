# -*- coding: utf-8 -*-
"""Scan background worker with task queue support."""
import os
import threading
import time
from datetime import datetime

try:
    from web import state
except ImportError:
    import state  # type: ignore

scan_state = state.scan_state
scan_lock = state.scan_lock
scan_stop_event = state.scan_stop_event


def _log(msg, task_id=None):
    state.log_scan(msg, task_id=task_id)


def _get_task_state(task_id):
    """获取任务状态，不存在返回None"""
    return state.scan_tasks.get(task_id)


# 已完成任务保留上限：scan_tasks 原来只增不减，每个任务长期持有全量 results 和 500 条日志
MAX_FINISHED_TASKS = 20
FINISHED_TASK_TTL = 3600.0  # 秒


def _prune_tasks():
    """淘汰已结束的老任务，防止 scan_tasks 内存单调增长。

    只清理 done/stopped/error 且不在运行的任务；正在运行/排队中的任务不受影响。
    """
    now = time.time()
    with scan_lock:
        # 先按 TTL 淘汰
        for tid in list(state.scan_tasks.keys()):
            t = state.scan_tasks.get(tid)
            if not t or t.get("running") or t.get("status") not in ("done", "stopped", "error"):
                continue
            end = t.get("end_time") or t.get("start_time") or now
            if now - end > FINISHED_TASK_TTL:
                state.scan_tasks.pop(tid, None)
        # 再按数量淘汰最旧的
        finished = sorted(tid for tid, t in state.scan_tasks.items()
                          if not t.get("running") and t.get("status") in ("done", "stopped", "error"))
        if len(finished) > MAX_FINISHED_TASKS:
            for tid in finished[:-MAX_FINISHED_TASKS]:
                state.scan_tasks.pop(tid, None)


def _update_current_view(task_id):
    """把指定任务的状态同步到全局scan_state（兼容前端）"""
    task = _get_task_state(task_id)
    if not task:
        return
    with scan_lock:
        scan_state["task_id"] = task_id
        scan_state["running"] = task["running"]
        scan_state["progress"] = task["progress"]
        scan_state["total"] = task["total"]
        scan_state["scanned"] = task["scanned"]
        scan_state["open_count"] = task["open_count"]
        scan_state["results"] = task["results"]
        scan_state["start_time"] = task["start_time"]


def _start_queued_workers():
    """从队列尽可能多地启动排队任务（不超过并发上限）。

    每个 worker 结束时调用一次；锁内 pop 保证不会重复启动同一任务。
    注意：scan_lock 是非重入锁，锁内禁止调用 _log（log_scan 内部会再次取锁），
    因此日志统一在锁外输出。
    """
    with scan_lock:
        running_count = sum(1 for t in state.scan_tasks.values() if t.get("running"))
        started_ids = []
        while running_count < state.max_concurrent_scans and state.scan_queue:
            next_id = state.scan_queue.pop(0)
            task = state.scan_tasks.get(next_id)
            if not task:
                continue
            queued_targets = task.pop("_queued_targets", None)
            queued_config = task.pop("_queued_config", None)
            if not queued_targets or not queued_config:
                task["status"] = "error"
                task["running"] = False
                continue
            task["status"] = "running"
            task["running"] = True
            state.current_task_id = next_id  # 主视图指向最新启动的任务
            running_count += 1
            started_ids.append(next_id)
            thread = threading.Thread(target=_scan_worker, args=(next_id, queued_targets, queued_config), daemon=True)
            thread.start()
        if running_count == 0:
            state.current_task_id = None
            scan_state["running"] = False
    for tid in started_ids:
        _update_current_view(tid)
        _log(f"任务 #{tid} 从队列启动", task_id=tid)
    if started_ids:
        _log(f"并发调度: 新启动 {len(started_ids)} 个任务，当前运行 {running_count} 个")
    return len(started_ids)


def start_scan_task(targets_list, scan_config, scan_type="manual"):
    """启动扫描任务。并发数未达上限直接启动，超出排队。返回task_id。"""
    with scan_lock:
        state.task_counter += 1
        task_id = state.task_counter
        task = state.new_task_state(task_id, len(targets_list), scan_type)
        state.scan_tasks[task_id] = task
        # 在锁内统计运行中的任务数，避免竞态
        running_count = sum(1 for t in state.scan_tasks.values() if t.get("running"))
        if running_count >= state.max_concurrent_scans:
            task["status"] = "queued"
            task["_queued_targets"] = targets_list
            task["_queued_config"] = scan_config
            state.scan_queue.append(task_id)
            queue_len = len(state.scan_queue)
            should_start = False
        else:
            task["status"] = "running"
            task["running"] = True
            state.current_task_id = task_id
            queue_len = 0
            should_start = True
    if should_start:
        thread = threading.Thread(target=_scan_worker, args=(task_id, targets_list, scan_config), daemon=True)
        thread.start()
    else:
        _log(f"任务 #{task_id} 已排队（当前运行{running_count}个/上限{state.max_concurrent_scans}个，前方{queue_len}个任务）",
             task_id=task_id)
    return task_id


def stop_task(task_id=None):
    """停止指定任务，不传则停止当前任务"""
    if task_id is None:
        task_id = state.current_task_id
    task = _get_task_state(task_id)
    if task:
        task["stop_event"].set()
        task["status"] = "stopped"
        _log(f"任务 #{task_id} 已停止", task_id=task_id)
    # 如果是排队中的任务，直接移除
    with scan_lock:
        if task_id in state.scan_queue:
            state.scan_queue.remove(task_id)
            if task:
                task["status"] = "stopped"
    return task_id


def list_tasks():
    """返回所有任务列表"""
    with scan_lock:
        tasks = []
        for tid, t in state.scan_tasks.items():
            tasks.append({
                "task_id": tid,
                "status": t["status"],
                "running": t["running"],
                "progress": t["progress"],
                "total": t["total"],
                "scanned": t["scanned"],
                "open_count": t["open_count"],
                "results_count": len(t["results"]),
                "start_time": t["start_time"],
                "end_time": t["end_time"],
                "scan_type": t["scan_type"],
                "is_current": (tid == state.current_task_id),
                "queue_position": state.scan_queue.index(tid) + 1 if tid in state.scan_queue else 0,
            })
        # 按task_id倒序
        tasks.sort(key=lambda x: x["task_id"], reverse=True)
        return tasks


def _scan_worker(task_id, targets_list, scan_cfg):
    """扫描工作线程，每个任务独立状态"""
    task = _get_task_state(task_id)
    if not task:
        return
    stop_evt = task["stop_event"]

    try:
        with scan_lock:
            task["running"] = True
            task["status"] = "running"
            task["start_time"] = time.time()
            task["results"] = []
            task["progress"] = 0
            task["scanned"] = 0
            task["open_count"] = 0
        _update_current_view(task_id)
        _log(f"任务 #{task_id} 开始，目标数: {len(targets_list)}", task_id=task_id)

        # 进度回调
        def _on_progress(done, total, open_count):
            with scan_lock:
                task["scanned"] = done
                task["total"] = total
                task["progress"] = int(done * 100 / total) if total else 0
                task["open_count"] = open_count
            _update_current_view(task_id)

        use_masscan = scan_cfg.get("use_masscan", False)
        portscan_only = scan_cfg.get("portscan_only", False)
        results = []

        # auto模式：目标数>=256 或 端口数>50 且系统有masscan时自动启用
        if use_masscan == "auto":
            from scanner.masscan import has_masscan
            target_count = len(targets_list) if isinstance(targets_list, list) else 1
            port_count = len(scan_cfg.get("ports", [25565]))
            has_mc = has_masscan()
            use_masscan = has_mc and (target_count >= 256 or port_count > 50)
            if use_masscan:
                _log(f"自动启用masscan加速（目标{target_count}个，端口{port_count}个）", task_id=task_id)
            elif not has_mc:
                _log("未检测到masscan，使用Python端口扫描（安装masscan可大幅提速）", task_id=task_id)
            else:
                _log(f"目标规模较小（目标{target_count}/端口{port_count}），使用Python扫描", task_id=task_id)
        elif isinstance(use_masscan, str):
            # 规范化字符串值：always/true→True，never/false/其他→False
            use_masscan = use_masscan.lower() in ("always", "true", "1", "yes")

        # 连续扫描模式
        if scan_cfg.get("continuous"):
            import ipaddress
            subnets = []
            for t in targets_list:
                if isinstance(t, (tuple, list)):
                    t = str(t[0]).strip()
                else:
                    t = str(t).strip()
                if not t:
                    continue
                try:
                    net = ipaddress.ip_network(t, strict=False)
                    if net.prefixlen < 24:
                        for subnet in net.subnets(new_prefix=24):
                            subnets.append(str(subnet))
                    else:
                        subnets.append(t)
                except ValueError:
                    continue
            from scanner.engine import ScanEngine
            engine = ScanEngine(stop_event=stop_evt,
                db_path=scan_cfg.get("db_path", "mcscanner.db"),
                workers=scan_cfg.get("workers", 32),
                timeout=scan_cfg.get("timeout", 4.0),
                auth_check=scan_cfg.get("auth_check", True),
                rate_limit=scan_cfg.get("rate", 0),
            )
            for i, subnet in enumerate(subnets):
                if stop_evt.is_set():
                    break
                _log(f"连续扫描 [{i+1}/{len(subnets)}]: {subnet}", task_id=task_id)
                # 展开CIDR为IP列表（subnets已被拆成/24，最多256个IP）
                net = ipaddress.ip_network(subnet, strict=False)
                ips = [str(ip) for ip in net.hosts()]
                if not ips:
                    continue
                subnet_results = engine.scan_with_portscan(
                    iter([(ip, p) for ip in ips for p in scan_cfg.get("ports", [25565])]),
                    scan_threads=scan_cfg.get("scan_threads", 200),
                    scan_timeout=scan_cfg.get("scan_timeout", 2.5),
                    progress_callback=_on_progress,
                )
                results.extend(subnet_results)
        elif use_masscan:
            from scanner.masscan import parse_masscan_json, run_masscan
            _log("使用 masscan 快速端口扫描")
            # targets_list 是 [(ip,port),...]，提取去重IP给masscan（masscan不认元组字符串）
            masscan_targets = ",".join(sorted(set(ip for ip, _ in targets_list)))
            masscan_ports = ",".join(str(p) for p in scan_cfg.get("ports", [25565]))
            # 显式传 output_file/timeout/stop_event：不传的话 masscan 的临时 NDJSON 只能靠
            # 进程退出时清理，且卡住的 masscan 无法被"停止扫描"中断
            import tempfile
            _fd, output_file = tempfile.mkstemp(suffix=".ndjson", prefix="masscan_")
            os.close(_fd)
            try:
                run_masscan(masscan_targets, ports=masscan_ports,
                            rate=scan_cfg.get("masscan_rate", 1000),
                            output_file=output_file,
                            timeout=float(scan_cfg.get("masscan_timeout", 600)),
                            stop_event=stop_evt)
                open_ports = list(parse_masscan_json(output_file))
            finally:
                # 自己传的 output_file 不会被 scanner.masscan 的临时表回收，必须在这里删
                try:
                    os.remove(output_file)
                except OSError:
                    pass
            # parse_masscan_json 返回 (ip,port,banner) 三元组，probe_list 要 (ip,port) 二元组
            open_pairs = [(ip, port) for ip, port, _ in open_ports]
            _log(f"masscan 发现 {len(open_pairs)} 个开放端口，开始SLP探测")
            if not portscan_only:
                from scanner.engine import ScanEngine
                from storage import db
                engine = ScanEngine(stop_event=stop_evt,
                    db_path=scan_cfg.get("db_path", "mcscanner.db"),
                    workers=scan_cfg.get("workers", 32),
                    timeout=scan_cfg.get("timeout", 4.0),
                    auth_check=scan_cfg.get("auth_check", True),
                )
                results = engine.probe_list(open_pairs, progress_callback=_on_progress)
                # probe_list 的 docstring 明确"不存数据库"：masscan 分支原来跑完显示成功，
                # 库里却一条没有（与 Python 分支行为不一致），这里显式落库
                if results:
                    db.upsert_many(scan_cfg.get("db_path", "mcscanner.db"), results)
            else:
                results = [{"ip": ip, "port": port, "state": "open",
                            "version": "", "motd": "", "players_online": 0, "players_max": 0,
                            "ping_ms": None, "proto": None}
                           for ip, port in open_pairs]
                _log(f"端口扫描完成，开放: {len(results)} 个")
        else:
            if scan_cfg.get("async_mode"):
                from scanner.async_engine import AsyncScanEngine
                from scanner.async_portscan import has_uvloop
                from scanner.async_probe import has_simdjson
                _log(f"异步流水线扫描（uvloop: {'启用' if has_uvloop() else '未安装'}, "
                     f"simdjson: {'启用' if has_simdjson() else '未安装'}）", task_id=task_id)
                # 语义对照（勿互换）：scan_threads（UI: scanThreads）= 端口扫描并发 → concurrency；
                # workers（UI: probeWorkers，config.py 注释"SLP探测线程数"）= SLP 并发 → slp_concurrency。
                # scanner 侧还会按扫描模式对 SLP 并发封顶（safe 模式压到 20）并打提示。
                async_engine = AsyncScanEngine(
                    db_path=scan_cfg.get("db_path", "mcscanner.db"),
                    concurrency=scan_cfg.get("scan_threads", 1000),
                    slp_concurrency=scan_cfg.get("workers", 200),
                    timeout=scan_cfg.get("timeout", 4.0),
                    auth_check=scan_cfg.get("auth_check", True),
                    rate_limit=scan_cfg.get("rate", 0),
                    stop_event=stop_evt,
                    mode=scan_cfg.get("scan_mode", "balanced"),
                )
                results = async_engine.scan_with_portscan(targets_list)
            else:
                from scanner.engine import ScanEngine
                engine = ScanEngine(stop_event=stop_evt,
                    db_path=scan_cfg.get("db_path", "mcscanner.db"),
                    workers=scan_cfg.get("workers", 32),
                    timeout=scan_cfg.get("timeout", 4.0),
                    auth_check=scan_cfg.get("auth_check", True),
                    rate_limit=scan_cfg.get("rate", 0),
                    mode=scan_cfg.get("scan_mode", "balanced"),
                )
                results = engine.scan_with_portscan(
                    targets_list,
                    scan_threads=scan_cfg.get("scan_threads", 200),
                    scan_timeout=scan_cfg.get("scan_timeout", 2.5),
                    progress_callback=_on_progress,
                )

        with scan_lock:
            task["results"] = results
            task["progress"] = 100
            task["total"] = len(results)
            task["status"] = "done"
            task["end_time"] = time.time()
        _update_current_view(task_id)
        _log(f"扫描完成，共发现 {len(results)} 个服务器", task_id=task_id)

        # 邮件通知
        try:
            from core.notifier import notify_scan_complete
            duration = time.time() - task.get("start_time", time.time())
            ok, err = notify_scan_complete(results, len(targets_list), duration, task_id)
            if ok:
                _log("扫描完成邮件已发送", task_id=task_id)
            elif err and "未启用" not in err:
                _log(f"邮件通知失败: {err}", task_id=task_id)
        except Exception as e:
            _log(f"邮件通知异常: {e}", task_id=task_id)

        # 历史记录
        with scan_lock:
            history_entry = {
                "id": task_id,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "targets": len(targets_list),
                "found": len(results),
                "mode": "masscan" if use_masscan else ("portscan" if portscan_only else "full"),
            }
            scan_state["history"].insert(0, history_entry)
            if len(scan_state["history"]) > 20:
                scan_state["history"] = scan_state["history"][:20]
    except Exception as e:
        _log(f"扫描出错: {e}", task_id=task_id)
        with scan_lock:
            task["status"] = "error"
            task["error"] = str(e)
            task["end_time"] = time.time()
    finally:
        with scan_lock:
            task["running"] = False
        # 从队列启动后续任务（可能同时启动多个，直到达到并发上限）
        _start_queued_workers()
        # 任务结束后回收老任务状态，避免长时间运行内存单调增长
        _prune_tasks()
