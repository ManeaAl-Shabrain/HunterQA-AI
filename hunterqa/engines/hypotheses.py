"""Human-review research checklists; not automatic exploitation or zero-day findings."""
CATEGORIES = {
  "Memory safety": ["Heap lifetime, ownership and UAF", "Bounds checks before allocation and copy", "Integer size overflow and double free"],
  "Injection": ["Trace untrusted inputs to interpreter/query sinks", "Check templating and deserialization boundaries"],
  "Authentication": ["Review session rotation, reset flows and MFA transition"],
  "Authorization": ["Compare object access across two approved test roles", "Check tenant and resource ownership enforcement"],
  "Web": ["Review output encoding, SSRF egress, CSRF, uploads and path traversal"],
  "APIs": ["Compare documented security schemes and enforcement", "Review mass assignment and BOLA boundaries"],
  "Cryptography": ["Check randomness, storage and rotation of keys", "Review outdated algorithms and TLS configuration"],
  "Business logic": ["Document invariants for state transitions and concurrency"],
  "Supply chain": ["Inventory dependencies and compare against locally verified advisories"],
  "Cloud and containers": ["Check IAM privilege boundaries and isolation policy"],
  "Availability": ["Review limits and resource exhaustion using bounded isolated tests"],
}


def checklist() -> list[dict]:
    return [{"category": name, "questions": questions, "status": "manual_research_required"} for name, questions in CATEGORIES.items()]
