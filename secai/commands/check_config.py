"""``secai check-config``: security audit of configuration files.

The input may be firewall rules, sshd_config, nginx.conf, docker-compose...
First :func:`secai.validators.guess_config_type` guesses the type (so the prompt is more precise),
then the AI audits it, and finally a rich table renders "issue / risk / remediation".
"""

from __future__ import annotations

from typing import Any

import click
from rich.console import Group
from rich.text import Text

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
from secai.parsing import parse_object
from secai.prompts import check_config_system
from secai.render import (
    bullet_list,
    fallback_panel,
    findings_table,
    info_panel,
    kv_table,
    severity_badge,
    summary_text,
)
from secai.validators import guess_config_type, normalize_severity


@click.command(name="check-config")
@click.argument("config_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--max-bytes",
    type=click.IntRange(1000),
    default=12000,
    show_default=True,
    help="Maximum number of bytes sent to the AI; anything beyond is truncated (controls cost)",
)
@click.option("--focus", default=None, help="A topic to focus on, e.g. ssh, tls, iptables")
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
def check_config(
    ctx: click.Context,
    config_file: str,
    max_bytes: int,
    focus: str | None,
    encoding: str,
    fail_on: str,
    local_json: bool = False,
    local_dry_run: bool = False,
) -> None:
    """Check a configuration file (firewall / SSH / Nginx / Docker...) for security issues.

    Examples:

        secai check-config firewall.rules
        secai check-config sshd_config --focus ssh
    """
    app: AppContext = resolve_app(ctx, local_json=local_json, local_dry_run=local_dry_run)
    content = read_text_file(config_file, encoding=encoding, max_bytes=max_bytes)
    config_type = guess_config_type(content.path.name, content.text)

    if not app.output_json:
        app.console.print(
            info_panel(
                kv_table(
                    {
                        "File": str(content.path),
                        "Size": f"{content.size_bytes} bytes",
                        "Detected type": config_type,
                        "Content sent": "Truncated" if content.truncated else "Complete",
                    }
                ),
                title="Configuration audit",
                style="cyan",
            )
        )
        if content.truncated:
            app.console.print(
                f"[yellow]Note: the content exceeds --max-bytes={max_bytes}, so only the beginning is analysed; "
                "raise --max-bytes to send more (increases token cost).[/yellow]"
            )

    response = request_ai(
        app,
        command=f"check-config {content.path.name}",
        system_prompt=check_config_system(config_type, focus),
        user_input=content.text,
    )
    if response is None:  # --dry-run
        return

    result = parse_object(
        response.text,
        required=("findings", "risk_level", "summary", "issues", "vulnerabilities"),
    )
    data: dict[str, Any] = result.data if isinstance(result.data, dict) else {}
    findings = _attach_location(result.findings)
    risk_level = normalize_severity(data.get("risk_level"))

    threshold_input = list(findings)
    if risk_level not in ("info", "unknown"):
        threshold_input.append({"title": "Overall risk assessment", "severity": risk_level})

    if app.output_json:
        emit_json(
            app,
            {
                "command": "check-config",
                "file": str(content.path),
                "config_type": config_type,
                "truncated": content.truncated,
                "parsed": result.ok,
                "risk_level": risk_level,
                "summary": data.get("summary"),
                "findings": normalized_finding_payload(findings),
                "hardening_tips": data.get("hardening_tips") or [],
                "raw": None if result.ok else result.raw,
                "parse_error": result.error,
            },
        )
        enforce_fail_on(app, threshold_input, fail_on)
        return

    _render(app, content.path.name, response, result, data, findings, risk_level)
    enforce_fail_on(app, threshold_input, fail_on)


def _attach_location(findings: list[dict]) -> list[dict]:
    """Merge ``location`` into the description so the table shows where the issue is."""
    prepared: list[dict] = []
    for finding in findings:
        item = dict(finding)
        location = item.get("location") or item.get("rule")
        description = str(item.get("description") or item.get("reason") or "")
        if location and str(location) not in description:
            note = f"location: {str(location)[:40]}"
            description = f"{description} ({note})" if description else note
        if description:
            item["description"] = description
        prepared.append(item)
    return prepared


def _render(
    app: AppContext,
    filename: str,
    response: Any,
    result: Any,
    data: dict[str, Any],
    findings: list[dict],
    risk_level: str,
) -> None:
    """Print the audit result (falls back to a plain-text panel when structure parsing fails)."""
    if not result.ok:
        app.console.print(fallback_panel(result, title=f"Audit result: {filename}"))
        app.console.print(usage_footer(response))
        return

    if not findings:
        app.console.print(
            info_panel(
                Group(
                    summary_text(findings),
                    Text(str(data.get("summary") or "")),
                    Text(),
                    severity_badge(risk_level) if risk_level != "unknown" else Text(),
                ),
                title=f"Audit result: {filename}",
                style="green",
            )
        )
        if data.get("hardening_tips"):
            app.console.print(
                info_panel(bullet_list(data["hardening_tips"]), title="Further hardening advice", style="green")
            )
        app.console.print(usage_footer(response))
        return

    app.console.print(
        info_panel(
            Group(
                Text("Overall risk: ", style="bold") + severity_badge(risk_level),
                Text(),
                findings_table(findings, title=f"Audit result: {filename}"),
            ),
            title=f"Configuration audit: {filename}",
            style="red" if risk_level in ("critical", "high") else "yellow",
        )
    )
    if data.get("summary"):
        app.console.print(info_panel(Text(str(data["summary"])), title="Summary", style="cyan"))
    if data.get("hardening_tips"):
        app.console.print(
            info_panel(bullet_list(data["hardening_tips"]), title="Further hardening advice", style="green")
        )
    app.console.print(usage_footer(response))
