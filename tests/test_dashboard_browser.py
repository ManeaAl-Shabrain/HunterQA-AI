"""Real Chromium verification of the local dashboard, CSP, and saved evidence UI."""
import json
import os
import threading

import pytest

from hunterqa.engagement import ENGINE


@pytest.mark.skipif(os.environ.get("HUNTERQA_ENGAGEMENT_BROWSER_CI") != "1", reason="Opt-in owned dashboard Chromium test")
def test_dashboard_scripts_and_assessment_page(app, approved_root, monkeypatch):
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.serving import make_server

    monkeypatch.setenv("HUNTERQA_APPROVED_ROOTS", str(approved_root))
    report = approved_root / "assessment.json"
    report.write_text(json.dumps({"schema_version": 1, "engine": ENGINE,
        "plan_sha256": "a" * 64, "policy_sha256": "b" * 64, "requests": 1, "stopped": False,
        "observations": [{"mode": "observe", "target_sha256": "c" * 64,
                          "status": 200, "verification": "unverified_observation"}],
        "review_required": True, "claims": {"verified_vulnerabilities": 0, "confirmed_zero_days": 0, "cve_ids_created": 0}}))
    app.config["ENGAGEMENT_REPORT_PATH"] = str(report)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with sync_playwright() as driver:
            browser = driver.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": 1365, "height": 900})
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("console", lambda message: errors.append(message.text) if "Content Security Policy" in message.text else None)
                page.goto(f"http://127.0.0.1:{server.server_port}/assessments")
                expect(page.get_by_role("heading", name="Saved assessments")).to_be_visible()
                expect(page.locator(".stat")).to_have_count(4)
                page.goto(f"http://127.0.0.1:{server.server_port}/research")
                expect(page.locator("#evidence-checked")).not_to_have_text("Not yet checked")
                assert not errors
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
