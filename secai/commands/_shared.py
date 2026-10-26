"""Shared command utilities: Context, file reading, dry-run, threshold checks, output.

Command modules only compose these helpers and never touch requests or rich details directly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.text import Text

from secai.ai_client import AIResponse, DeepSeekClient
from secai.exceptions import EXIT_FINDINGS, FileReadError, InvalidInputError
from secai.render import (
    info_panel,
    print_json_payload,
    severity_badge,
    severity_rank,
)
from secai.validators import normalize_severity

#: Legal values for ``--fail-on`` (none means never fail because of findings)
FAIL_ON_CHOICES = ("none", "info", "low", "medium", "high", "critical")


@dataclass
class AppContext:
    """Execution environment shared across commands."""

    console: Console
    ai: DeepSeekClient
    dry_run: bool = False
    output_json: bool = False
    verbose: bool = False
    #: Console used for diagnostics (retry notices, verbose lines, warnings). ``cli`` points this
    #: at stderr when ``--json`` is active, so stdout keeps carrying exactly one JSON document.
    diag_console: Console | None = None

    def diag(self, message: object) -> None:
        """Print a diagnostic line without ever corrupting the ``--json`` output."""
        target = self.diag_console if self.diag_console is not None else self.console
        target.print(message)


@dataclass
class FileContent:
    """A file read result (including truncation information)."""

    path: Path
    text: str
    size_bytes: int
    truncated: bool = False

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def line_count(self) -> int:
        return len(self.lines)


def app_of(ctx: click.Context) -> AppContext:
    """Get the :class:`AppContext` from the click context."""
    app = ctx.obj
    if not isinstance(app, AppContext):  # pragma: no cover - programming error
        raise RuntimeError("the click context is missing AppContext")
    return app


def output_flags(func):
    """Also accept ``--json`` / ``--dry-run`` on subcommands (equivalent to the global options).

    click requires global options to come *before* the subcommand
    (``secai --json scan-url URL``), yet users naturally write
    ``secai scan-url URL --json``. Re-attaching the same flags to every subcommand
    supports both spellings.
    """

    func = click.option(
        "--dry-run",
        "local_dry_run",
        is_flag=True,
        help="Same as the global --dry-run (print what would be sent without calling the API)",
    )(func)
    func = click.option(
        "--json",
        "local_json",
        is_flag=True,
        help="Same as the global --json (emit JSON, handy for CI pipelines)",
    )(func)
    return func


def resolve_app(
    ctx: click.Context,
    *,
    local_json: bool = False,
    local_dry_run: bool = False,
) -> AppContext:
    """Get the :class:`AppContext` and apply the subcommand-level ``--json`` / ``--dry-run``."""
    app = app_of(ctx)
    if local_json:
        app.output_json = True
    if local_dry_run:
        app.dry_run = True
    return app


def read_text_file(path: str | Path, *, encoding: str = "utf-8", max_bytes: int | None = None) -> FileContent:
    """Read a text file, handling common errors and supporting truncation.

    :raises FileReadError: the file is a directory, permission denied, or it cannot be decoded.
    :raises InvalidInputError: the file is empty.
    """
    file_path = Path(path)
    if file_path.is_dir():
        raise FileReadError(f"'{file_path}' is a directory, not a file")

    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        raise FileReadError(f"Unable to read file '{file_path}'", hint=str(exc)) from exc

    truncated = False
    if max_bytes is not None and len(raw) > max_bytes:
        raw = raw[:max_bytes]
        truncated = True

    try:
        text = raw.decode(encoding, errors="replace")
    except LookupError as exc:
        raise InvalidInputError(f"Unsupported encoding '{encoding}'", hint=str(exc)) from exc

    if not text.strip():
        raise InvalidInputError(f"File '{file_path}' is empty, there is nothing to analyse")

    return FileContent(path=file_path, text=text, size_bytes=file_path.stat().st_size, truncated=truncated)


def request_ai(
    app: AppContext,
    *,
    command: str,
    system_prompt: str,
    user_input: str,
    json_mode: bool = True,
) -> AIResponse | None:
    """Call the AI; in ``--dry-run`` mode only print what would be sent and return ``None``.

    Returning ``None`` means the caller should stop immediately (dry-run mode).
    """
    payload = app.ai.build_payload(system_prompt, user_input, json_mode=json_mode)

    if app.dry_run:
        if app.output_json:
            print_json_payload(
                app.console,
                {
                    "dry_run": True,
                    "command": command,
                    "endpoint": app.ai.endpoint,
                    "payload": payload,
                },
            )
        else:
            app.console.print(
                info_panel(
                    Text(json.dumps(payload, ensure_ascii=False, indent=2)),
                    title=f"[dry-run] {command} | nothing is actually sent (no API quota used)",
                    style="magenta",
                )
            )
            app.console.print(
                Text(
                    "Hint: set DEEPSEEK_API_KEY, drop --dry-run, and you will get a real analysis.",
                    style="dim",
                )
            )
        return None

    if app.verbose:
        app.diag(Text(f"[verbose] {app.ai.describe()}", style="dim"))

    return app.ai.complete(system_prompt, user_input, json_mode=json_mode)


def usage_footer(response: AIResponse | None) -> Text:
    """Call statistics (model / tokens / retries)."""
    if response is None:  # pragma: no cover - dry-run never reaches this point
        return Text()
    parts = [f"model={response.model}"]
    if response.attempts > 1:
        parts.append(f"retries={response.attempts - 1}")
    if response.prompt_tokens is not None or response.completion_tokens is not None:
        parts.append(f"tokens={response.prompt_tokens or 0}+{response.completion_tokens or 0}")
    parts.append(f"elapsed={response.elapsed:.1f}s")
    return Text(" · ".join(parts), style="dim")


def enforce_fail_on(app: AppContext, findings: list[dict], fail_on: str) -> None:
    """Exit with :data:`EXIT_FINDINGS` when a finding reaches the ``--fail-on`` threshold.

    This is what makes the tool usable in CI: ``secai check-config fw.rules --fail-on high || exit 1``.
    """
    if fail_on == "none" or not findings:
        return
    threshold = severity_rank(fail_on)
    worst = max(findings, key=lambda item: severity_rank(item.get("severity")))
    if severity_rank(worst.get("severity")) < threshold:
        return

    if app.output_json:
        # Keep --json output clean (exactly one JSON document); only the exit code signals the threshold.
        raise click.exceptions.Exit(EXIT_FINDINGS)

    app.console.print(
        Text("\nThreshold reached: ", style="bold red")
        + Text("found a ")
        + severity_badge(worst.get("severity"))
        + Text(f" level finding (--fail-on {fail_on}), exiting with code {EXIT_FINDINGS}.")
    )
    raise click.exceptions.Exit(EXIT_FINDINGS)


def emit_json(app: AppContext, payload: dict[str, Any]) -> None:
    """Output for ``--json`` mode."""
    print_json_payload(app.console, payload)


def normalized_finding_payload(findings: list[dict]) -> list[dict[str, Any]]:
    """For JSON output: keep only the stable fields."""
    keys = ("severity", "line", "title", "type", "category", "rule", "source",
            "reason", "description", "remediation", "location")
    payload: list[dict[str, Any]] = []
    for finding in findings:
        item = {key: finding[key] for key in keys if finding.get(key) not in (None, "")}
        item["severity"] = normalize_severity(finding.get("severity"))
        payload.append(item)
    return payload
