"""``secai cve``: structured CVE analysis.

Design notes: the AI's vulnerability knowledge may be outdated or hallucinated,
so besides asking for ``uncertain_fields`` the output always ends with a
"defer to the official advisory" reminder, and ``--json`` is supported so other tools can post-process it.
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
    output_flags,
    request_ai,
    resolve_app,
    usage_footer,
)
from secai.parsing import parse_object
from secai.prompts import CVE_SYSTEM
from secai.render import (
    bullet_list,
    fallback_panel,
    info_panel,
    kv_table,
    severity_badge,
)
from secai.validators import normalize_cve_id, normalize_severity

DISCLAIMER = "AI-generated vulnerability information may be outdated or wrong; defer to NVD / the vendor advisory."


@click.command(name="cve")
@click.argument("cve_id")
@output_flags
@click.option(
    "--fail-on",
    type=click.Choice(FAIL_ON_CHOICES),
    default="none",
    show_default=True,
    help="Exit with code 10 when the severity reaches the threshold (useful for CI)",
)
@click.pass_context
def cve(
    ctx: click.Context,
    cve_id: str,
    fail_on: str,
    local_json: bool = False,
    local_dry_run: bool = False,
) -> None:
    """Look up CVE details, affected scope, and remediation advice.

    Example:

        secai cve CVE-2024-1234
    """
    app: AppContext = resolve_app(ctx, local_json=local_json, local_dry_run=local_dry_run)
    normalized = normalize_cve_id(cve_id)

    if app.verbose:
        app.diag(f"[verbose] Normalised CVE ID: {normalized}")

    response = request_ai(
        app,
        command=f"cve {normalized}",
        system_prompt=CVE_SYSTEM,
        user_input=normalized,
    )
    if response is None:  # --dry-run
        return

    if response.finish_reason == "length":
        app.diag("[yellow]Warning: the response was cut off by the length limit; parsing may be incomplete.[/yellow]")

    result = parse_object(
        response.text,
        required=("description", "severity", "remediation", "title", "cvss_score"),
    )
    data = result.data if isinstance(result.data, dict) else {}
    severity = normalize_severity(data.get("severity"))
    finding = {"title": data.get("title") or normalized, "severity": severity}

    if app.output_json:
        emit_json(
            app,
            {
                "command": "cve",
                "cve_id": normalized,
                "parsed": result.ok,
                "data": data if result.ok else None,
                "raw": None if result.ok else result.raw,
                "parse_error": result.error,
                "disclaimer": DISCLAIMER,
            },
        )
        enforce_fail_on(app, [finding], fail_on)
        return

    if not result.ok or not data:
        app.console.print(fallback_panel(result, title=f"CVE analysis: {normalized}"))
        app.console.print(f"[dim]{DISCLAIMER}[/dim]")
        enforce_fail_on(app, [finding], fail_on)
        return

    header = kv_table(
        {
            "CVE": str(data.get("cve_id") or normalized),
            "Title": data.get("title"),
            "Severity": severity_badge(severity),
            "CVSS": data.get("cvss_score"),
            "CVSS vector": data.get("cvss_vector"),
            "CWE": data.get("cwe"),
            "Affected systems": data.get("affected_systems"),
            "Exploitability": data.get("exploitability"),
        }
    )

    sections: list[Any] = [header]
    if data.get("description"):
        sections.extend([Text(), Text(str(data["description"]))])
    app.console.print(
        info_panel(Group(*sections), title=f"CVE analysis: {normalized}", style="red")
    )

    if data.get("remediation"):
        app.console.print(info_panel(bullet_list(data["remediation"]), title="Remediation", style="green"))
    if data.get("detection"):
        app.console.print(info_panel(bullet_list(data["detection"]), title="Detection signs", style="cyan"))
    if data.get("references"):
        app.console.print(info_panel(bullet_list(data["references"]), title="References", style="blue"))
    if data.get("uncertain_fields"):
        app.console.print(
            info_panel(
                bullet_list(data["uncertain_fields"]),
                title="Fields the AI flagged as uncertain (please verify manually)",
                style="yellow",
            )
        )

    app.console.print(usage_footer(response))
    app.console.print(f"[dim]{DISCLAIMER}[/dim]")
    enforce_fail_on(app, [finding], fail_on)
