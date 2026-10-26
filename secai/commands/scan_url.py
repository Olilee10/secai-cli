"""``secai scan-url``: URL risk assessment (passive analysis, no offensive scanning).

Deliberately built on two tracks:

* **Local heuristics**: objective, testable, and usable offline (``--no-ai``).
* **AI analysis**: adds semantic judgement (what this endpoint probably does, where the attack surface is).

The risk score is computed only after merging both, and the table labels each source so the result is
explainable and auditable.
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
    request_ai,
    resolve_app,
    usage_footer,
)
from secai.heuristics import (
    highest_severity,
    merge_findings,
    score_from_findings,
    url_heuristics,
)
from secai.parsing import ParseResult, parse_object
from secai.prompts import SCAN_URL_SYSTEM
from secai.render import (
    bullet_list,
    fallback_panel,
    findings_table,
    info_panel,
    risk_bar,
    severity_badge,
)
from secai.validators import normalize_severity, normalize_url


@click.command(name="scan-url")
@click.argument("url")
@click.option("--no-ai", is_flag=True, help="Run only the local heuristics, no AI call (no API key needed)")
@click.option(
    "--fail-on",
    type=click.Choice(FAIL_ON_CHOICES),
    default="none",
    show_default=True,
    help="Exit with code 10 when the severity reaches the threshold (useful for CI)",
)
@output_flags
@click.pass_context
def scan_url(
    ctx: click.Context,
    url: str,
    no_ai: bool,
    fail_on: str,
    local_json: bool = False,
    local_dry_run: bool = False,
) -> None:
    """Assess the risk of a URL (purely passive; no attack request is ever sent to the target).

    Examples:

        secai scan-url https://example.com/api/admin
        secai scan-url "http://10.0.0.5/x.php?file=../../etc/passwd" --no-ai
    """
    app: AppContext = resolve_app(ctx, local_json=local_json, local_dry_run=local_dry_run)
    target = normalize_url(url)
    heuristic_findings = url_heuristics(target)

    findings: list[dict] = list(heuristic_findings)
    ai_data: dict[str, Any] = {}
    parsed_ok = True
    dry_run = False
    response = None
    parse_result: ParseResult | None = None

    payload_preview: dict[str, Any] | None = None
    if not no_ai:
        if app.output_json and app.dry_run:
            # In --json mode this command emits one single JSON document: build the payload locally
            # so request_ai does not print a second payload and concatenate two JSON documents.
            payload_preview = app.ai.build_payload(
                SCAN_URL_SYSTEM, target.normalized, json_mode=True
            )
            dry_run = True
        else:
            response = request_ai(
                app,
                command=f"scan-url {target.normalized}",
                system_prompt=SCAN_URL_SYSTEM,
                user_input=target.normalized,
            )
            if response is None:  # --dry-run
                dry_run = True
            else:
                parse_result = parse_object(
                    response.text,
                    required=("findings", "risk_level", "risk_score", "summary", "issues"),
                )
                ai_data = parse_result.data if isinstance(parse_result.data, dict) else {}
                parsed_ok = parse_result.ok
                findings = merge_findings(parse_result.findings, heuristic_findings)

    risk_level = normalize_severity(ai_data.get("risk_level"))
    if risk_level == "unknown":
        risk_level = highest_severity(findings)

    score = score_from_findings(findings)
    ai_score = ai_data.get("risk_score")
    if isinstance(ai_score, (int, float)) and not isinstance(ai_score, bool):
        score = max(score, int(ai_score))
    score = max(0, min(score, 100))

    threshold_input = list(findings)
    if risk_level not in ("info", "unknown"):
        threshold_input.append({"title": "Overall risk assessment", "severity": risk_level})

    if app.output_json:
        emit_json(
            app,
            {
                "command": "scan-url",
                "url": target.normalized,
                "host": target.host,
                "scheme": target.scheme,
                "port": target.port,
                "dry_run": dry_run,
                "no_ai": bool(no_ai),
                "request": payload_preview,
                "parsed": parsed_ok,
                "risk_level": risk_level,
                "risk_score": score,
                "summary": ai_data.get("summary"),
                "findings": normalized_finding_payload(findings),
                "verification_steps": ai_data.get("verification_steps") or [],
                "assumptions": ai_data.get("assumptions") or [],
                "raw": None if parsed_ok else (parse_result.raw if parse_result else None),
                "parse_error": parse_result.error if parse_result else None,
            },
        )
        enforce_fail_on(app, threshold_input, fail_on)
        return

    app.console.print(
        info_panel(
            Group(
                Text(target.normalized, style="bold"),
                Text(),
                Text("Risk score: ") + risk_bar(score),
                Text("Overall level: ", style="bold") + severity_badge(risk_level),
            ),
            title="URL risk assessment" + (" (dry-run: local rules only)" if dry_run else ""),
            style="red" if score >= 70 else ("yellow" if score >= 40 else "cyan"),
        )
    )

    if dry_run:
        app.console.print("[magenta]dry-run: the AI was not called; the results below come from local heuristics only.[/magenta]")

    if not parsed_ok and parse_result is not None:
        app.console.print(fallback_panel(parse_result, title="AI analysis (plain-text mode)"))
    elif ai_data.get("summary"):
        app.console.print(info_panel(Text(str(ai_data["summary"])), title="AI summary", style="cyan"))

    if findings:
        app.console.print(
            info_panel(
                findings_table(findings, title="Risk list", show_source=True),
                title="Findings",
                style="yellow",
            )
        )
    else:
        app.console.print(
            info_panel(Text("Neither the local rules nor the AI found any obvious issue.", style="bold green"), title="Findings")
        )

    if ai_data.get("verification_steps"):
        app.console.print(
            info_panel(
                bullet_list(ai_data["verification_steps"]), title="Suggested (passive) verification", style="green"
            )
        )
    if ai_data.get("assumptions"):
        app.console.print(
            info_panel(bullet_list(ai_data["assumptions"]), title="Assumptions behind the AI's judgement", style="dim")
        )

    app.console.print(usage_footer(response))
    enforce_fail_on(app, threshold_input, fail_on)
