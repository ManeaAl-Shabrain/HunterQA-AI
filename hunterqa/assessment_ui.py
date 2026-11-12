"""Only bounded offline synthetic analysis is launchable through this UI."""
import json
import threading
import uuid
from pathlib import Path

from flask import current_app

_DEMO_SLOT = threading.BoundedSemaphore(1)


def run_demo(module, project):
    from .assessment_demo import run
    from .assessment_history import record
    from .assessment_modes import MODULES
    from .db import get_db
    if module != "all" and module not in MODULES:
        raise ValueError("Unknown demo module")
    if project and (not project.isascii() or not project.isdigit() or len(project) > 10):
        raise ValueError("Choose an existing project")
    project_id = int(project) if project else None
    if project_id is not None and not get_db().execute("SELECT id FROM projects WHERE id=?", (project_id,)).fetchone():
        raise ValueError("Unknown project")
    if not _DEMO_SLOT.acquire(blocking=False):
        raise BlockingIOError("Demonstration capacity reached")
    try:
        root = Path(current_app.config["WORKSPACE_ROOT"]) / "assessments"
        destination = root / "evidence" / ("demo-" + uuid.uuid4().hex)
        result = run(destination, module=module, authorized=True)
        if not result["all_cases_matched"]:
            raise ValueError("Synthetic baseline differs")
        binding = {"database": current_app.config["DATABASE"], "operator_database": current_app.config["OPERATOR_DATABASE"],
            "workspace_id": current_app.config["WORKSPACE_ID"], "root": str(root), "project_id": project_id}
        ids = []
        for item in result["reports"]:
            path = destination / item["report_file"]
            report = json.loads(path.read_text(encoding="utf-8"))
            ids.append(record(binding, path, report))
        return ids[-1]
    finally:
        _DEMO_SLOT.release()
