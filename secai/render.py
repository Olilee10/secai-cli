"""rich terminal output.

All CLI presentation logic lives here; command modules only "get data -> call render", so the
output style stays consistent and the command logic stays testable (no formatting code mixed in).
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Iterable, Sequence

from rich.console import Console, Group
from rich.json import JSON as RichJSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from secai.exceptions import SecAIError
from secai.parsing import ParseResult
from secai.validators import SEVERITY_STYLE, normalize_severity, severity_rank

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")


def ensure_utf8_output() -> None:
    """Make sure standard output can be written as UTF-8.

    Windows consoles (cmd.exe / PowerShell) often default to cp950 or cp1252, and writing
    non-ASCII text directly raises ``UnicodeEncodeError``. Before the Console is created the
    streams are switched to UTF-8 (``errors="replace"``) so the CLI works in any terminal.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # for example a third-party test double
            continue
        encoding = (getattr(stream, "encoding", None) or "").lower()
        if encoding.replace("-", "").replace("_", "").startswith("utf8"):
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - keep as is when the stream refuses
            pass


def build_console(*, stderr: bool = False) -> Console:
    """Create a Console with the shared style.

    ``SECAI_NO_COLOR=1`` (or the standard ``NO_COLOR``) forces colours off, which is handy
    when piping output into a file or CI log.
    """
    ensure_utf8_output()
    no_color = bool(os.getenv("SECAI_NO_COLOR") or os.getenv("NO_COLOR"))
    return Console(
        stderr=stderr,
        no_color=no_color,
        highlight=False,
        soft_wrap=False,
        emoji=False,
    )


def severity_badge(severity: object) -> Text:
    """Return a colourised severity badge."""
    normalized = normalize_severity(severity)
    label = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW"}.get(
        normalized, normalized.upper()
    )
    return Text(label, style=SEVERITY_STYLE.get(normalized, "bold magenta"))


def severity_legend() -> Text:
    """The severity legend used in output."""
    text = Text()
    for index, severity in enumerate(("critical", "high", "medium", "low", "info")):
        if index:
            text.append("  ")
        text.append_text(severity_badge(severity))
    return text


def sort_findings(findings: Iterable[dict]) -> list[dict]:
    """Sort by severity high to low (ties keep their original order so line numbers line up)."""
    return sorted(findings, key=lambda item: -severity_rank(item.get("severity")))


def count_by_severity(findings: Iterable[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def summary_text(findings: Sequence[dict]) -> Text:
    """Build a one-line summary such as ``HIGH 2  MED 1``."""
    counts = count_by_severity(findings)
    if not counts:
        return Text("No issues found", style="bold green")
    text = Text()
    for index, severity in enumerate(SEVERITY_ORDER):
        if severity not in counts:
            continue
        if index and text:
            text.append("  ")
        text.append_text(severity_badge(severity))
        text.append(f" ×{counts[severity]}", style="dim")
    return text


def truncate(value: object, limit: int = 60) -> str:
    """Shorten a long string so the table does not blow up."""
    text = " ".join(str(value if value is not None else "").split())
    if len(text) <= limit:
        return text
    return text[: max(limit - 1, 1)] + "…"


def findings_table(
    findings: Sequence[dict],
    *,
    title: str | None = None,
    show_line: bool = False,
    show_source: bool = False,
    caption: str | None = None,
) -> Table:
    """Render a finding list as a table.

    :param show_line: show the ``line`` field (used by log analysis).
    :param show_source: show the finding source (``ai`` / ``heuristic``).
    """
    table = Table(
        title=title,
        caption=caption,
        header_style="bold",
        title_justify="left",
        caption_justify="left",
        expand=True,
    )
    table.add_column("Severity", no_wrap=True)
    if show_line:
        table.add_column("Line", justify="right", no_wrap=True)
    if show_source:
        table.add_column("Source", no_wrap=True)
    table.add_column("Type", no_wrap=False, max_width=28)
    table.add_column("Details", overflow="fold")
    table.add_column("Remediation", overflow="fold", max_width=36)

    for finding in sort_findings(findings):
        remediation = (
            finding.get("remediation") or finding.get("advice") or finding.get("fix") or "—"
        )
        if isinstance(remediation, (list, tuple)):
            remediation = " / ".join(str(item) for item in remediation)
        reason = (
            finding.get("reason")
            or finding.get("description")
            or finding.get("detail")
            or "—"
        )
        row: list[Any] = [severity_badge(finding.get("severity"))]
        if show_line:
            line = finding.get("line")
            row.append(str(line) if line is not None else "-")
        if show_source:
            source = str(finding.get("source") or "ai").lower()
            row.append("Heuristic" if source.startswith("heur") else "AI")
        row.extend([Text(truncate(finding.get("title"), 28)), str(reason), str(remediation)])
        table.add_row(*row)
    return table


def findings_panel(findings: Sequence[dict], *, title: str, show_line: bool = False) -> Panel:
    """A Panel combining the summary line and the findings table."""
    body = Group(
        summary_text(findings),
        Text(),
        findings_table(findings, show_line=show_line),
    )
    style = "red" if any(severity_rank(f.get("severity")) >= 3 for f in findings) else "yellow"
    return Panel(body, title=title, border_style=style, title_align="left")


def fallback_panel(result: ParseResult, *, title: str) -> Panel:
    """Show the raw text when the AI did not return valid JSON."""
    body = Group(
        Text("The AI did not return parsable structured output; raw response below (plain text mode)", style="bold yellow"),
        Text(result.error or "", style="dim"),
        Text(),
        Text(result.raw or "(empty response)"),
    )
    return Panel(body, title=title, border_style="yellow", title_align="left")


def risk_bar(score: int, *, width: int = 24) -> Text:
    """Draw a 0-100 risk score as a progress bar."""
    score = max(0, min(int(score), 100))
    filled = round(width * score / 100)
    if score >= 70:
        style = "bold red"
    elif score >= 40:
        style = "bold yellow"
    elif score >= 15:
        style = "bold cyan"
    else:
        style = "bold green"
    text = Text()
    text.append("█" * filled, style=style)
    text.append("░" * (width - filled), style="dim")
    text.append(f"  {score}/100", style=style)
    return text


def kv_table(data: dict[str, Any], *, key_width: int = 14) -> Table:
    """A two-column (key/value) table, used for CVE details."""
    table = Table.grid(padding=(0, 1))
    table.add_column(style="bold cyan", no_wrap=True, min_width=key_width)
    table.add_column(overflow="fold")
    for key, value in data.items():
        if value in (None, "", [], {}):
            continue
        table.add_row(key, _render_value(value))
    return table


def _render_value(value: Any) -> Any:
    if isinstance(value, Text):
        return value
    if isinstance(value, (list, tuple)):
        return Group(*[Text(f"• {item}") for item in value]) if value else ""
    if isinstance(value, dict):
        return RichJSON(json.dumps(value, ensure_ascii=False, indent=2))
    return Text(str(value))


def bullet_list(items: Iterable[Any], *, style: str | None = None) -> Group:
    """Render a list as bullets."""
    return Group(*[Text(f"• {item}", style=style) for item in items])


def info_panel(body: Any, *, title: str, style: str = "cyan") -> Panel:
    return Panel(body, title=title, border_style=style, title_align="left")


def print_error(console: Console, error: SecAIError) -> None:
    """Print an error panel (including hint and exit code)."""
    body = Group(Text(error.message, style="bold red"))
    if error.hint:
        body.renderables.append(Text())
        body.renderables.append(Text(error.hint, style="dim"))
    console.print(
        Panel(
            body,
            title=f"{error.title} (exit {error.exit_code})",
            border_style="red",
            title_align="left",
        )
    )


def print_json_payload(console: Console, payload: Any) -> None:
    """``--json`` mode: emit machine-readable JSON only."""
    console.print_json(json.dumps(payload, ensure_ascii=False, default=str))

