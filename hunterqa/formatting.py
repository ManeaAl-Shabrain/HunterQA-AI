"""Safely render a minimal subset of Markdown for untrusted Ollama reports."""
from __future__ import annotations
import re
from markupsafe import Markup, escape


def safe_report_markdown(source: str) -> Markup:
    result=[]
    in_list=False
    for raw in str(source or "")[:120_000].splitlines():
        line=raw.strip()
        if not line:
            if in_list:
                result.append("</ul>")
                in_list=False
            continue
        heading=re.match(r"^(#{1,3})\s+(.+)$",line)
        bullet=re.match(r"^[-*]\s+(.+)$",line)
        if in_list and not bullet:
            result.append("</ul>")
            in_list=False
        if heading:
            level=len(heading.group(1))+1  # h2-h4 inside report
            result.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
        elif bullet:
            if not in_list:
                result.append("<ul>")
                in_list=True
            result.append(f"<li>{_inline(bullet.group(1))}</li>")
        else:
            result.append(f"<p>{_inline(line)}</p>")
    if in_list:
        result.append("</ul>")
    # _inline escapes all imported text before the fixed renderer adds HTML tags.
    return Markup("\n".join(result))  # nosec B704


def _inline(text: str) -> str:
    safe=str(escape(text))
    safe=re.sub(r"\*\*(.+?)\*\*",r"<strong>\1</strong>",safe)
    safe=re.sub(r"`([^`]{1,300})`",r"<code>\1</code>",safe)
    return safe
