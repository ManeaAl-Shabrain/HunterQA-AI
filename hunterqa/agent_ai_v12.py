"""Private optional Ollama assistant for bounded specialist-agent *recommendations*.

Nothing is executed. The model receives vetted, aggregate plan metadata only:
no credentials, raw captures, target URLs, source files or API endpoints.
Any unexpected model output is rejected rather than used as a tool invocation.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .agent_workflow_v12 import SKILL_BY_ID
from .bounty import _read_json

LOCAL_OLLAMA = "http://127.0.0.1:11434/api/generate"
ALLOWED_MODELS = ("qwen2.5-coder:3b", "qwen2.5-coder:7b")
MAX_CONTEXT = 8_000
MAX_RESPONSE = 20_000
MAX_SUGGESTIONS = 5


def _ask_ollama(prompt, model):
    body = json.dumps({
        "model": model, "prompt": prompt, "stream": False, "format": "json",
        "options": {"temperature": 0.1, "num_predict": 512},
    }).encode("utf-8")
    request = urllib.request.Request(
        LOCAL_OLLAMA, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "HunterQA-AI/1.2-local"},
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        data = response.read(MAX_RESPONSE + 1)
    if len(data) > MAX_RESPONSE:
        raise ValueError("Ollama response exceeds 20 KB limit")
    container = json.loads(data)
    return container.get("response", "") if isinstance(container, dict) else ""


def suggest_reviews(plan_path, *, authorized=False, model="qwen2.5-coder:3b",
                    transport=None):
    if not authorized:
        raise PermissionError("Local AI engagement review requires --authorized")
    if model not in ALLOWED_MODELS:
        raise ValueError("Only reviewed local Ollama models are supported")
    plan = _read_json(plan_path, MAX_CONTEXT * 2)
    if (not isinstance(plan, dict) or
            plan.get("engine") != "hunterqa_v12_approved_agent_plan" or
            not isinstance(plan.get("steps"), list) or len(plan["steps"]) > 12 or
            not isinstance(plan.get("metrics"), dict)):
        raise ValueError("Expected a bounded HunterQA agent plan")
    # Values in the prompt come only from vetted role names and numeric counts.
    enabled = []
    for step in plan["steps"]:
        if isinstance(step, dict) and step.get("enabled") is True:
            role = step.get("agent_id")
            if role in SKILL_BY_ID and role not in enabled:
                enabled.append(role)
    ops = plan["metrics"].get("api_contract_operations")
    if type(ops) is not int or not 0 <= ops <= 500:
        raise ValueError("Invalid operation count in plan")
    prompt = (
        "You are a private security research triage assistant. Choose up to five "
        "specialist review roles for authorized, non-destructive, offline investigation. "
        "Do not propose payloads, exploitation, credential access, stealth, evasion, "
        "commands, networking, scanning or CVE claims. The only output is JSON: "
        '{"suggestions":[{"agent_id":"role-id","reason":"short manual-review rationale"}]}. '
        "Allowed role ids: " + ", ".join(enabled) + ". "
        "The local OpenAPI inventory contains " + str(ops) + " operations. "
        "Give concise human-review priorities and no other fields."
    )
    assert len(prompt) < MAX_CONTEXT
    output = {
        "schema_version": 1, "engine": "hunterqa_v12_local_ai_review",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": model, "status": "unavailable", "suggestions": [],
        "network_scope": "loopback_ollama_only",
        "commands_executed": 0, "confirmed_vulnerabilities": 0,
        "limitations": "Model suggestions are untrusted manual review priorities, "
                       "not evidence, exploitation steps or confirmed vulnerabilities.",
    }
    try:
        raw = (transport or _ask_ollama)(prompt, model)
        if not isinstance(raw, str) or len(raw) > MAX_RESPONSE:
            raise ValueError("Invalid local model response size")
        data = json.loads(raw)
        items = data.get("suggestions") if isinstance(data, dict) else None
        if not isinstance(items, list) or len(items) > MAX_SUGGESTIONS:
            raise ValueError("Model did not return bounded suggestions")
        seen = set()
        suggestions = []
        for item in items:
            if not isinstance(item, dict):
                continue
            role, reason = item.get("agent_id"), item.get("reason")
            if role not in enabled or role in seen or not isinstance(reason, str):
                continue
            reason = re.sub(r"[\x00-\x1f\x7f]", " ", reason).strip()
            if not 10 <= len(reason) <= 200:
                continue
            # A model can select an approved role but cannot supply a tool call.
            suggestions.append({"agent_id": role,
                                "mission": SKILL_BY_ID[role]["mission"],
                                "reason": reason, "action": "human_review_only"})
            seen.add(role)
        output["status"] = "review_candidates" if suggestions else "no_accepted_suggestions"
        output["suggestions"] = suggestions
    except (OSError, TimeoutError, urllib.error.URLError, ValueError, TypeError,
            KeyError, json.JSONDecodeError):
        output["status"] = "unavailable_or_invalid_output"
    return output
