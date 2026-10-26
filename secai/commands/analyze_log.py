"""``secai analyze-log``: log anomaly analysis.

Design:

1. Read the file, then split it into batches by ``--batch-size`` (bounds token usage and the impact of a single failure).
2. Send each batch to the AI as "real line number + content" and ask it to report only suspicious lines.
3. **Hallucination guard**: if the AI reports line numbers outside the current batch they are dropped and counted (never polluting the report).
4. A batch that fails to parse degrades to plain-text mode without affecting the other batches.
5. The optional ``--fail-on`` lets CI break the build based on severity.
"""

from __future__ import annotations

from contextlib import nullcontext
from typing import Any, Iterator

import click
from rich.console import Group
from rich.text import Text

from secai.ai_client import AIResponse
from secai.commands._shared import (
    FAIL_ON_CHOICES,
    AppContext,
    emit_json,
    enforce_fail_on,
    normalized_finding_payload,
    output_flags,
    read_text_file,
    request_ai,
    resolve_app,
    usage_footer,
)
from secai.parsing import parse_findings
from secai.prompts import ANALYZE_LOG_SYSTEM
from secai.render import (
    bullet_list,
    findings_panel,
    findings_table,
    info_panel,
    kv_table,
    summary_text,
)

#: Maximum length of a single log line sent for analysis (prevents one line from blowing up the prompt)
MAX_LINE_CHARS = 400


@click.command(name="analyze-log")
@click.argument("log_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--batch-size",
    type=click.IntRange(1, 200),
    default=12,
    show_default=True,
    help="How many lines to send to the AI per batch (smaller is cheaper and less likely to time out)",
)
@click.option(
    "--max-lines",
    type=click.IntRange(0),
    default=200,
    show_default=True,
    help="Analyse at most this many lines (0 = all)",
)
@click.option("--show-all", is_flag=True, help="Also display lines the AI judged normal")
@click.option("--encoding", default="utf-8", show_default=True, help="File encoding")
@click.option(
    "--fail-on",
    type=click.Choice(FAIL_ON_CHOICES),
    default="none",
    show_default=True,
    help="Exit with code 10 when the severity reaches the threshold (useful for CI)",
)
@output_flags
@click.pass_context
def analyze_log(
    ctx: click.Context,
    log_file: str,
    batch_size: int,
    max_lines: int,
    show_all: bool,
    encoding: str,
    fail_on: str,
    local_json: bool = False,
    local_dry_run: bool = False,
) -> None:
    """Analyse a log file to find suspicious activity (brute force, scanning, injection attempts...).

    \b
    Examples:
      secai analyze-log access.log
      secai analyze-log access.log --batch-size 20 --max-lines 500
      secai analyze-log auth.log --fail-on high --json
    """
    app: AppContext = resolve_app(ctx, local_json=local_json, local_dry_run=local_dry_run)
    content = read_text_file(log_file, encoding=encoding)
    lines = content.lines
    selected = lines[:max_lines] if max_lines else lines

    batches = list(_iter_batches(selected, batch_size))
    if not app.output_json:
        app.console.print(
            info_panel(
                kv_table(
                    {
                        "File": str(content.path),
                        "Total lines": len(lines),
                        "Lines analysed": len(selected),
                        "Batches": f"{len(batches)} batches ({batch_size} lines each)",
                    }
                ),
                title="Log analysis",
                style="cyan",
            )
        )
        if max_lines and len(lines) > max_lines:
            app.console.print(
                f"[yellow]Note: only the first {max_lines} of {len(lines)} lines are analysed; "
                "adjust with --max-lines.[/yellow]"
            )

    if not batches:
        app.console.print("[yellow]There are no non-empty lines to analyse.[/yellow]")
        return

    findings: list[dict] = []
    fallback_texts: list[str] = []
    notes: list[str] = []
    dropped_lines = 0
    responses: list[AIResponse] = []

    for index, batch in enumerate(batches, start=1):
        user_input = "\n".join(f"{number}: {text[:MAX_LINE_CHARS]}" for number, text in batch)
        with _progress(app, f"Analysing batch {index}/{len(batches)}"):
            response = request_ai(
                app,
                command=f"analyze-log {content.path.name} (batch {index}/{len(batches)})",
                system_prompt=ANALYZE_LOG_SYSTEM,
                user_input=user_input,
            )
        if response is None:  # --dry-run
            return
        responses.append(response)

        parsed = parse_findings(
            response.text, list_keys=("findings", "anomalies", "issues", "results")
        )
        if not isinstance(parsed.data, (dict, list)):
            # No JSON extractable at all (prose, HTML...) -> render this batch as plain text
            fallback_texts.append(f"[batch {index}] {parsed.raw}")
            continue

        valid_numbers = {number for number, _ in batch}
        for finding in parsed.findings:
            line_number = finding.get("line")
            if line_number is not None and line_number not in valid_numbers:
                dropped_lines += 1
                continue
            if not show_all and finding.get("is_anomaly") is False:
                continue
            findings.append(finding)

        note = _batch_note(parsed.data, index)
        if note:
            notes.append(note)

    anomalies = [item for item in findings if item.get("is_anomaly") is not False]
    token_usage = _token_usage(responses)

    if app.output_json:
        emit_json(
            app,
            {
                "command": "analyze-log",
                "file": str(content.path),
                "lines_total": len(lines),
                "lines_analyzed": len(selected),
                "batches": len(batches),
                "findings": normalized_finding_payload(findings),
                "anomaly_count": len(anomalies),
                "dropped_out_of_range_lines": dropped_lines,
                "summary": notes,
                "fallback_batches": len(fallback_texts),
                "token_usage": token_usage,
            },
        )
        # --json mode emits a single JSON document (fallback information is already part of the
        # fallback_batches field of the payload) and enforce_fail_on prints nothing in this mode.
        enforce_fail_on(app, anomalies, fail_on)
        return

    _render(
        app,
        content.path.name,
        findings,
        fallback_texts,
        notes,
        dropped_lines,
        token_usage,
        responses[-1] if responses else None,
    )
    enforce_fail_on(app, anomalies, fail_on)


def _iter_batches(lines: list[str], batch_size: int) -> Iterator[list[tuple[int, str]]]:
    """Split the log into batches of ``(original line number, content)``, skipping blank lines."""
    batch: list[tuple[int, str]] = []
    for number, text in enumerate(lines, start=1):
        if not text.strip():
            continue
        batch.append((number, text))
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _batch_note(data: Any, index: int) -> str | None:
    """Extract a batch's summary / benign_notes as manual review hints."""
    if not isinstance(data, dict):
        return None
    for key in ("summary", "benign_notes"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return f"Batch {index}: {value.strip()}"
    return None


def _token_usage(responses: list[AIResponse]) -> dict[str, int]:
    """Aggregate token usage and call count."""
    prompt = sum(response.prompt_tokens or 0 for response in responses)
    completion = sum(response.completion_tokens or 0 for response in responses)
    return {"prompt_tokens": prompt, "completion_tokens": completion, "calls": len(responses)}


def _progress(app: AppContext, message: str):
    """Show a spinner only on a terminal, to keep pipe / CI output clean."""
    return app.console.status(message) if app.console.is_terminal else nullcontext()


def _render(
    app: AppContext,
    filename: str,
    findings: list[dict],
    fallback_texts: list[str],
    notes: list[str],
    dropped_lines: int,
    token_usage: dict[str, int],
    last_response: AIResponse | None,
) -> None:
    """Print the analysis result."""
    anomalies = [item for item in findings if item.get("is_anomaly") is not False]

    if anomalies:
        app.console.print(findings_panel(anomalies, title=f"Anomalies found: {filename}", show_line=True))
    else:
        app.console.print(
            info_panel(
                Group(summary_text([]), Text("No suspicious activity found.", style="bold green")),
                title=f"Analysis result: {filename}",
                style="green",
            )
        )

    benign = [item for item in findings if item.get("is_anomaly") is False]
    if benign:
        app.console.print(
            info_panel(
                Group(
                    Text("Lines the AI marked as normal, kept for review:", style="dim"),
                    findings_table(benign, show_line=True),
                ),
                title="Normal lines (--show-all)",
                style="blue",
            )
        )

    if notes:
        app.console.print(info_panel(bullet_list(notes), title="Batch summaries", style="cyan"))

    if fallback_texts:
        app.console.print(
            info_panel(
                bullet_list(fallback_texts), title="Batches that could not be parsed (plain-text mode)", style="yellow"
            )
        )

    if dropped_lines:
        app.console.print(
            f"[dim]Dropped {dropped_lines} finding(s) with line numbers outside their batch "
            "(AI hallucination guard).[/dim]"
        )

    if token_usage.get("calls"):
        app.console.print(
            f"[dim]{token_usage['calls']} API call(s) · "
            f"tokens={token_usage['prompt_tokens']}+{token_usage['completion_tokens']}[/dim]"
        )
    if last_response is not None:
        app.console.print(usage_footer(last_response))
