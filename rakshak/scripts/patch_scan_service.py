"""Patch scan_service.py: instant terminate + per-scan concurrency."""
import os

path = os.path.join(os.path.dirname(__file__), '..', 'app', 'services', 'scan_service.py')
path = os.path.abspath(path)

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('\r\n', '\n')

# ═══════════════════════════════════════════════════════════════════
# Patch 1: Add scan_active_tasks dict + cancel_scan_tasks() function
# ═══════════════════════════════════════════════════════════════════

old_globals = '''# Global dict: scan_id -> list of progress messages (for WebSocket delivery)
scan_progress: dict[int, list[dict]] = {}
scan_cancel_events: dict[int, asyncio.Event] = {}'''

new_globals = '''# Global dict: scan_id -> list of progress messages (for WebSocket delivery)
scan_progress: dict[int, list[dict]] = {}
scan_cancel_events: dict[int, asyncio.Event] = {}
# Track in-flight asyncio.Tasks per scan for instant cancellation
scan_active_tasks: dict[int, set[asyncio.Task]] = {}

# Per-scan concurrency budget — prevents one scan from starving another
PER_SCAN_CONCURRENCY = 20


async def cancel_scan_tasks(scan_id: int):
    """Instantly cancel all in-flight tasks for a scan.
    
    This calls task.cancel() on every running asyncio.Task,
    which raises CancelledError at the next await point inside
    _scan_single / scan_target / _oqs_probe / _run_command_async,
    killing any Docker exec subprocesses immediately.
    """
    cancel_event = scan_cancel_events.get(scan_id)
    if cancel_event:
        cancel_event.set()

    tasks = scan_active_tasks.get(scan_id, set())
    for task in tasks:
        if not task.done():
            task.cancel()
    logger.info(f"cancel_scan_tasks: cancelled {len(tasks)} in-flight tasks for scan {scan_id}")'''

if old_globals in content:
    content = content.replace(old_globals, new_globals, 1)
    print("Patch 1: OK (globals + cancel_scan_tasks)")
else:
    print("Patch 1: FAILED — globals not found")

# ═══════════════════════════════════════════════════════════════════
# Patch 2: Rewrite run_scan loop for instant cancellation
# ═══════════════════════════════════════════════════════════════════

old_run_scan = '''    cancel_event = scan_cancel_events.setdefault(scan_id, asyncio.Event())

    async with AsyncSession() as db:
        # Update scan status to running
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            scan_cancel_events.pop(scan_id, None)
            return

        if scan.status == ScanStatus.cancelled:
            scan.completed_at = datetime.utcnow()
            await db.commit()
            scan_cancel_events.pop(scan_id, None)
            return

        scan.status = ScanStatus.running
        scan.started_at = datetime.utcnow()
        scan.target_count = len(targets)
        await db.commit()

        await push_progress(scan_id, {"phase": "started", "total": len(targets), "message": "Scan started"})

        completed = 0
        failed = 0
        

        
        async def process_target(idx, target):
            nonlocal completed, failed
            if cancel_event.is_set():
                return idx, target, None, None
            base_pct = round((idx / len(targets)) * 100)
            step_pct = max(1, round(100 / len(targets)))

            async def sub_progress(sub_phase, detail=""):
                sub_pcts = {"resolve": 0.0, "tls": 0.15, "oqs": 0.45, "classify": 0.75, "save": 0.90}
                sub_offset = sub_pcts.get(sub_phase, 0)
                pct = min(99, base_pct + round(step_pct * sub_offset))
                icons = {"resolve": "\U0001f50d", "tls": "\U0001f512", "oqs": "\U0001f433", "classify": "\U0001f3f7\ufe0f", "save": "\U0001f4be"}
                labels = {
                    "resolve": f"Resolving {target}...",
                    "tls": f"TLS handshake with {target}...",
                    "oqs": f"OQS Docker probe for {target}...",
                    "classify": f"Classifying PQC posture for {target}...",
                    "save": f"Saving results for {target}...",
                }
                await push_progress(scan_id, {
                    "phase": "scanning",
                    "sub_phase": sub_phase,
                    "target": target,
                    "current": idx + 1,
                    "total": len(targets),
                    "pct": pct,
                    "message": f"{icons.get(sub_phase,'')} {labels.get(sub_phase, detail)}",
                })

            await sub_progress("resolve")
            try:
                if cancel_event.is_set():
                    return idx, target, None, None
                await sub_progress("tls")
                scan_result_raw = await _scan_single(target)
                return idx, target, True, scan_result_raw
            except Exception as e:
                logger.exception(f"Error scanning {target}")
                return idx, target, False, e

        def progress_pct() -> int:
            if not targets:
                return 0
            return round(((completed + failed) / len(targets)) * 100)

        target_iter = iter(enumerate(targets))
        active_tasks: set[asyncio.Task] = set()

        def launch_next() -> bool:
            if cancel_event.is_set():
                return False
            try:
                idx, target = next(target_iter)
            except StopIteration:
                return False
            active_tasks.add(asyncio.create_task(process_target(idx, target)))
            return True

        for _ in range(min(50, len(targets))):
            if not launch_next():
                break

        cancel_notice_sent = False

        while active_tasks:
            done, _ = await asyncio.wait(active_tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                active_tasks.discard(task)
                idx, target, success, result_or_err = await task
                if success is None:
                    continue

                if cancel_event.is_set():
                    if not cancel_notice_sent:
                        await push_progress(scan_id, {
                            "phase": "cancel_requested",
                            "message": "Termination requested. Rakshak will keep only completed target results.",
                        })
                        cancel_notice_sent = True
                    continue

                if success:
                    try:
                        await save_scan_result(db, scan_id, target, result_or_err)
                        completed += 1
                        label = result_or_err.get("pqc_label", "unknown")
                        label_icons = {"fully_quantum_safe": "\U0001f7e2", "pqc_ready": "\U0001f535", "partially_quantum_safe": "\U0001f7e1", "not_quantum_safe": "\u274c", "unknown": "\u26aa", "intranet_only": "\U0001f512", "dns_failed": "\U0001f6ab"}
                        label_display = result_or_err.get("pqc_label_display", label.replace('_', ' ').title())
                        await push_progress(scan_id, {
                            "phase": "completed_target",
                            "target": target,
                            "current": completed + failed,
                            "total": len(targets),
                            "pct": progress_pct(),
                            "label": label,
                            "message": f"\u2705 {target} \u2192 {label_icons.get(label, '')} {label_display}",
                        })
                    except Exception as e:
                        logger.exception(f"Error saving {target}")
                        failed += 1
                else:
                    failed += 1
                    failed_result = ScanResult(
                        scan_id=scan_id,
                        target_url=target,
                        status="failed",
                        error_message=str(result_or_err),
                    )
                    db.add(failed_result)
                    await db.commit()

                    await push_progress(scan_id, {
                        "phase": "issue_target",
                        "target": target,
                        "message": f"Issue: {target} \u2014 {str(result_or_err)}",
                    })

                try:
                    result = await db.execute(select(Scan).where(Scan.id == scan_id))
                    scan = result.scalar_one_or_none()
                    if scan:
                        scan.completed_count = completed
                        scan.failed_count = failed
                        scan.progress_pct = progress_pct()
                        await db.commit()
                except Exception as e:
                    logger.error(f"Failed to update intermediate db progress: {e}")

                launch_next()

        # Recompute cyber rating safely
        try:
            await recompute_cyber_rating(db)
        except Exception as e:
            logger.error(f"Failed to recompute cyber rating: {e}")

        # Mark scan complete
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.cancelled if cancel_event.is_set() else ScanStatus.completed
                scan.completed_at = datetime.utcnow()
                scan.completed_count = completed
                scan.failed_count = failed
                scan.progress_pct = progress_pct() if cancel_event.is_set() else 100.0
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to mark scan as complete in DB: {e}")

        try:
            await push_progress(scan_id, {
                "phase": "done",
                "total": len(targets),
                "completed": completed,
                "failed": failed,
                "status": "cancelled" if cancel_event.is_set() else "completed",
                "message": (
                    f"Scan cancelled: {completed} completed targets kept, {failed} issues recorded."
                    if cancel_event.is_set()
                    else f"Scan complete: {completed} succeeded, {failed} issues recorded."
                ),
            })
        except Exception as e:
            logger.error(f"Failed to push final done progress: {e}")
        finally:
            scan_cancel_events.pop(scan_id, None)'''

new_run_scan = '''    cancel_event = scan_cancel_events.setdefault(scan_id, asyncio.Event())

    async with AsyncSession() as db:
        # Update scan status to running
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            scan_cancel_events.pop(scan_id, None)
            return

        if scan.status == ScanStatus.cancelled:
            scan.completed_at = datetime.utcnow()
            await db.commit()
            scan_cancel_events.pop(scan_id, None)
            return

        scan.status = ScanStatus.running
        scan.started_at = datetime.utcnow()
        scan.target_count = len(targets)
        await db.commit()

        await push_progress(scan_id, {"phase": "started", "total": len(targets), "message": "Scan started"})

        completed = 0
        failed = 0

        async def process_target(idx, target):
            """Scan one target. CancelledError is allowed to propagate for instant termination."""
            base_pct = round((idx / len(targets)) * 100)
            step_pct = max(1, round(100 / len(targets)))

            async def sub_progress(sub_phase, detail=""):
                sub_pcts = {"resolve": 0.0, "tls": 0.15, "oqs": 0.45, "classify": 0.75, "save": 0.90}
                sub_offset = sub_pcts.get(sub_phase, 0)
                pct = min(99, base_pct + round(step_pct * sub_offset))
                icons = {"resolve": "\U0001f50d", "tls": "\U0001f512", "oqs": "\U0001f433", "classify": "\U0001f3f7\ufe0f", "save": "\U0001f4be"}
                labels = {
                    "resolve": f"Resolving {target}...",
                    "tls": f"TLS handshake with {target}...",
                    "oqs": f"OQS Docker probe for {target}...",
                    "classify": f"Classifying PQC posture for {target}...",
                    "save": f"Saving results for {target}...",
                }
                await push_progress(scan_id, {
                    "phase": "scanning",
                    "sub_phase": sub_phase,
                    "target": target,
                    "current": idx + 1,
                    "total": len(targets),
                    "pct": pct,
                    "message": f"{icons.get(sub_phase,'')} {labels.get(sub_phase, detail)}",
                })

            await sub_progress("resolve")
            await sub_progress("tls")
            scan_result_raw = await _scan_single(target)
            return idx, target, True, scan_result_raw

        def progress_pct() -> int:
            if not targets:
                return 0
            return round(((completed + failed) / len(targets)) * 100)

        target_iter = iter(enumerate(targets))
        active_tasks: set[asyncio.Task] = set()
        # Register with global dict so cancel_scan_tasks() can reach us
        scan_active_tasks[scan_id] = active_tasks

        def launch_next() -> bool:
            if cancel_event.is_set():
                return False
            try:
                idx, target = next(target_iter)
            except StopIteration:
                return False
            active_tasks.add(asyncio.create_task(process_target(idx, target)))
            return True

        # Per-scan concurrency budget (not 50 — leaves room for concurrent scans)
        for _ in range(min(PER_SCAN_CONCURRENCY, len(targets))):
            if not launch_next():
                break

        while active_tasks:
            done, _ = await asyncio.wait(active_tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                active_tasks.discard(task)

                # Handle cancelled tasks (from cancel_scan_tasks)
                if task.cancelled():
                    continue

                try:
                    idx, target, success, result_or_err = task.result()
                except asyncio.CancelledError:
                    continue
                except Exception as e:
                    # process_target raised an unexpected exception
                    failed += 1
                    logger.exception(f"Error scanning target")
                    continue

                if cancel_event.is_set():
                    # Cancel was requested — don't save this result, just drain
                    continue

                if success:
                    try:
                        await save_scan_result(db, scan_id, target, result_or_err)
                        completed += 1
                        label = result_or_err.get("pqc_label", "unknown")
                        label_icons = {"fully_quantum_safe": "\U0001f7e2", "pqc_ready": "\U0001f535", "partially_quantum_safe": "\U0001f7e1", "not_quantum_safe": "\u274c", "unknown": "\u26aa", "intranet_only": "\U0001f512", "dns_failed": "\U0001f6ab"}
                        label_display = result_or_err.get("pqc_label_display", label.replace('_', ' ').title())
                        await push_progress(scan_id, {
                            "phase": "completed_target",
                            "target": target,
                            "current": completed + failed,
                            "total": len(targets),
                            "pct": progress_pct(),
                            "label": label,
                            "message": f"\u2705 {target} \u2192 {label_icons.get(label, '')} {label_display}",
                        })
                    except Exception as e:
                        logger.exception(f"Error saving {target}")
                        failed += 1
                else:
                    failed += 1
                    failed_result = ScanResult(
                        scan_id=scan_id,
                        target_url=target,
                        status="failed",
                        error_message=str(result_or_err),
                    )
                    db.add(failed_result)
                    await db.commit()

                    await push_progress(scan_id, {
                        "phase": "issue_target",
                        "target": target,
                        "message": f"Issue: {target} \u2014 {str(result_or_err)}",
                    })

                try:
                    result = await db.execute(select(Scan).where(Scan.id == scan_id))
                    scan = result.scalar_one_or_none()
                    if scan:
                        scan.completed_count = completed
                        scan.failed_count = failed
                        scan.progress_pct = progress_pct()
                        await db.commit()
                except Exception as e:
                    logger.error(f"Failed to update intermediate db progress: {e}")

                launch_next()

        # Recompute cyber rating safely
        try:
            await recompute_cyber_rating(db)
        except Exception as e:
            logger.error(f"Failed to recompute cyber rating: {e}")

        # Mark scan complete
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.cancelled if cancel_event.is_set() else ScanStatus.completed
                scan.completed_at = datetime.utcnow()
                scan.completed_count = completed
                scan.failed_count = failed
                scan.progress_pct = progress_pct() if cancel_event.is_set() else 100.0
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to mark scan as complete in DB: {e}")

        try:
            await push_progress(scan_id, {
                "phase": "done",
                "total": len(targets),
                "completed": completed,
                "failed": failed,
                "status": "cancelled" if cancel_event.is_set() else "completed",
                "message": (
                    f"Scan cancelled: {completed} completed targets kept, {failed} issues recorded."
                    if cancel_event.is_set()
                    else f"Scan complete: {completed} succeeded, {failed} issues recorded."
                ),
            })
        except Exception as e:
            logger.error(f"Failed to push final done progress: {e}")
        finally:
            scan_cancel_events.pop(scan_id, None)
            scan_active_tasks.pop(scan_id, None)'''

if old_run_scan in content:
    content = content.replace(old_run_scan, new_run_scan, 1)
    print("Patch 2: OK (run_scan rewrite)")
else:
    print("Patch 2: FAILED — run_scan body not found")
    # Debug: try to find a unique anchor
    idx = content.find('cancel_event = scan_cancel_events.setdefault(scan_id')
    if idx >= 0:
        print(f"  Found anchor at offset {idx}")
        print(f"  Context: {repr(content[idx:idx+80])}")
    else:
        print("  Could not find anchor either")

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)
print(f"Written to {path}")
