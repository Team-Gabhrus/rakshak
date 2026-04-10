"""Focused verification for discovery notifications and email sender headers.

Run from the `rakshak/` directory:

    python scripts/verify_discovery_notifications.py
"""
from __future__ import annotations

import asyncio
import os
import sys
from email.utils import parseaddr
from pathlib import Path
from unittest.mock import patch

import httpx

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
os.environ["DEBUG"] = "false"

from app.database import init_db  # noqa: E402
from app.main import app, seed_default_users  # noqa: E402
from app.services import email_service  # noqa: E402
from app.services.subdomain_service import (  # noqa: E402
    SubdomainScanState,
    subdomain_scan_states,
)


def log_result(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    suffix = f" - {detail}" if detail else ""
    print(f"[{status}] {name}{suffix}")


def expect(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"{name} failed. {detail}".strip())
    log_result(name, True, detail)


async def login_admin(client: httpx.AsyncClient) -> dict:
    res = await client.post("/api/auth/login", json={"username": "admin", "password": "admin@123"})
    expect("Admin login", res.status_code == 200, f"status={res.status_code}")
    data = res.json()
    expect("Admin login bypasses OTP", data.get("require_otp") is False)
    return {"Authorization": f"Bearer {data['access_token']}"}


async def verify_script() -> None:
    await init_db()
    await seed_default_users()

    checkpoint_job = "verify-prompt-checkpoint"
    scan_prompt_job = "verify-prompt-scan-ready"
    subdomain_scan_states.pop(checkpoint_job, None)
    subdomain_scan_states.pop(scan_prompt_job, None)

    checkpoint_state = SubdomainScanState(
        job_id=checkpoint_job,
        domain="notify-example.com",
        status="waiting_confirmation",
        processed_count=1000,
        live_count=111,
        dead_count=889,
        breadth_level=1,
        last_message="1000 results found. Continue Scanning?",
        pending_prompt={
            "kind": "checkpoint",
            "title": "Discovery Checkpoint",
            "message": "1000 results found. Continue Scanning?",
            "confirm_label": "Continue",
            "decline_label": "Stop Here",
        },
    )
    checkpoint_state.decision_event = asyncio.Event()
    subdomain_scan_states[checkpoint_job] = checkpoint_state

    scan_prompt_state = SubdomainScanState(
        job_id=scan_prompt_job,
        domain="notify-finished.com",
        status="awaiting_scan_confirmation",
        processed_count=42,
        live_count=12,
        dead_count=30,
        breadth_level=2,
        last_message="Discovery finished with 12 live target(s). Start the quantum vulnerability scan now?",
        pending_prompt={
            "kind": "scan_ready",
            "title": "Start Quantum Scan",
            "message": "Discovery finished with 12 live target(s). Start the quantum vulnerability scan now?",
            "confirm_label": "Start Scan",
            "decline_label": "Later",
        },
    )
    subdomain_scan_states[scan_prompt_job] = scan_prompt_state

    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            headers = await login_admin(client)

            status_res = await client.get("/api/tasks/status", headers=headers)
            expect("Task status endpoint", status_res.status_code == 200, f"status={status_res.status_code}")
            status_data = status_res.json()
            expect("Task status exposes action_required", status_data["counts"]["action_required"] >= 2)

            tasks_res = await client.get("/api/tasks", headers=headers)
            expect("Task inventory endpoint", tasks_res.status_code == 200, f"status={tasks_res.status_code}")
            tasks_data = tasks_res.json()
            discovery_jobs = {job["job_id"]: job for job in tasks_data["discovery_jobs"]}
            expect("Checkpoint job visible in tasks", checkpoint_job in discovery_jobs)
            expect("Scan-ready job visible in tasks", scan_prompt_job in discovery_jobs)
            expect("Checkpoint prompt kind preserved", discovery_jobs[checkpoint_job]["pending_prompt"]["kind"] == "checkpoint")
            expect("Scan-ready prompt kind preserved", discovery_jobs[scan_prompt_job]["pending_prompt"]["kind"] == "scan_ready")

            decision_res = await client.post(
                f"/api/assets/discover/subdomains/{checkpoint_job}/decision",
                json={"continue_scanning": True},
                headers=headers,
            )
            expect("Checkpoint decision endpoint", decision_res.status_code == 200, f"status={decision_res.status_code}")
            decision_data = decision_res.json()
            expect("Checkpoint prompt cleared after decision", decision_data.get("pending_prompt") is None)

            dismiss_res = await client.post(
                f"/api/assets/discover/subdomains/{scan_prompt_job}/dismiss",
                headers=headers,
            )
            expect("Scan prompt dismiss endpoint", dismiss_res.status_code == 200, f"status={dismiss_res.status_code}")
            dismiss_data = dismiss_res.json()
            expect("Dismiss completes scan-ready job", dismiss_data.get("status") == "completed")
            expect("Dismiss clears pending prompt", dismiss_data.get("pending_prompt") is None)

        captured = {}

        async def fake_send(msg, **kwargs):
            captured["from"] = msg["From"]
            captured["to"] = msg["To"]
            captured["subject"] = msg["Subject"]
            return None

        original_user = email_service.settings.SMTP_USER
        original_password = email_service.settings.SMTP_PASSWORD
        email_service.settings.SMTP_USER = "rakshak.gabrus@gmail.com"
        email_service.settings.SMTP_PASSWORD = "verification-password"
        try:
            with patch("app.services.email_service.aiosmtplib.send", new=fake_send):
                await email_service.send_report_email(
                    to_email="receiver@example.com",
                    subject="Verification",
                    body="Testing sender header",
                )
        finally:
            email_service.settings.SMTP_USER = original_user
            email_service.settings.SMTP_PASSWORD = original_password

        sender_name, sender_email = parseaddr(captured.get("from") or "")
        expect("Email sender display name", sender_name == "Rakshak (Team Gabrus)")
        expect("Email sender address", sender_email == "rakshak.gabrus@gmail.com")
    finally:
        subdomain_scan_states.pop(checkpoint_job, None)
        subdomain_scan_states.pop(scan_prompt_job, None)


if __name__ == "__main__":
    try:
        asyncio.run(verify_script())
    except Exception as exc:
        print(f"[FAIL] verification aborted - {exc}")
        raise
