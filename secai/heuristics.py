"""Deterministic local heuristics that do not depend on the API.

If ``scan-url`` relied on the LLM alone, results would be unstable and hard to test.
This module extracts the "deterministic, verifiable" URL traits first:

* The AI handles semantic judgement (what this endpoint probably does, where the attack surface is).
* The heuristic rules handle objective facts (plaintext HTTP, encoded traversal, redirect params...).

The two are merged before output, and the ``source`` field distinguishes their origin so
results stay explainable and auditable.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from secai.validators import SEVERITY_RANK, UrlTarget, normalize_severity

#: Score weight per severity, used to convert a finding list into a 0-100 risk score.
SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 2, "unknown": 2}

_TRAVERSAL_PATTERNS = (
    "../",
    "..\\",
    "%2e%2e",
    "%252e",
    "etc/passwd",
    "c:\\windows",
)

_SQLI_SIGNATURES = (
    "union select",
    "union+select",
    "or 1=1",
    "or%201=1",
    "' or '",
    "sleep(",
    "benchmark(",
    "information_schema",
)

_XSS_SIGNATURES = ("<script", "%3cscript", "onerror=", "javascript:", "%00")

_REDIRECT_PARAMS = frozenset(
    {
        "url",
        "uri",
        "redirect",
        "redirect_url",
        "next",
        "target",
        "dest",
        "destination",
        "return",
        "returnurl",
        "return_url",
        "continue",
        "goto",
        "callback",
        "image",
    }
)

_EXEC_PARAMS = frozenset(
    {
        "cmd",
        "exec",
        "command",
        "shell",
        "system",
        "eval",
        "include",
        "require",
        "file",
        "path",
        "page",
        "template",
        "tpl",
        "load",
        "import",
        "query",
        "sql",
    }
)

_SECRET_PARAMS = frozenset(
    {
        "api_key",
        "apikey",
        "token",
        "access_token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "session",
        "sessionid",
        "jwt",
        "signature",
        "sig",
    }
)

#: Path trait -> (severity, reason)
_SENSITIVE_PATHS = {
    "admin": ("medium", "Admin interfaces should usually not be exposed to the public internet"),
    "phpmyadmin": ("high", "An exposed database admin interface is a high-value target"),
    "wp-admin": ("medium", "The WordPress back end is a common brute-force target"),
    ".git": ("high", "Leaking the version control directory exposes the source code"),
    ".env": ("critical", ".env files often hold database passwords and API keys"),
    "actuator": ("medium", "Spring Actuator endpoints may leak environment variables and stack traces"),
    "swagger": ("low", "API documentation endpoints may expose internal interfaces"),
    "graphql": ("low", "Check whether introspection is disabled on the GraphQL endpoint"),
    "backup": ("medium", "Backup files can often be downloaded directly"),
    ".sql": ("high", "Database dump file exposure"),
    "debug": ("medium", "Debug endpoints may leak internal information"),
    "server-status": ("low", "The Apache status page leaks request information"),
    "console": ("high", "Console endpoints such as JMX/H2 often lead to RCE"),
    "jenkins": ("medium", "CI systems are high-value supply chain targets"),
    "wp-login.php": ("low", "The login page is a brute-force target"),
}


def url_heuristics(target: UrlTarget) -> list[dict]:
    """Apply the local rules to a URL and return the finding list (possibly empty)."""
    findings: list[dict] = []
    decoded_path = unquote(target.path).lower()
    decoded_query = unquote(target.query).lower()
    combined = f"{decoded_path}?{decoded_query}"

    def add(title: str, severity: str, description: str, remediation: str, rule: str) -> None:
        findings.append(
            {
                "title": title,
                "severity": severity,
                "description": description,
                "remediation": remediation,
                "rule": rule,
                "source": "heuristic",
            }
        )

    if target.scheme == "http":
        add(
            "Unencrypted HTTP connection",
            "medium",
            "Traffic is sent over plaintext HTTP, so credentials, cookies and tokens can be "
            "intercepted or tampered with by a man in the middle.",
            "Switch to HTTPS and enable HSTS; redirect HTTP to HTTPS with a 301.",
            "transport-plaintext",
        )

    host_part = target.normalized.split("://", 1)[-1].split("/", 1)[0]
    if "@" in host_part:
        add(
            "Credentials embedded in the URL",
            "high",
            "The user:password@host form writes credentials into browser history, logs and "
            "the Referer header.",
            "Pass credentials via an Authorization header or a cookie instead.",
            "credentials-in-url",
        )

    if ".." in decoded_path or any(pattern in combined for pattern in _TRAVERSAL_PATTERNS):
        add(
            "Possible directory traversal",
            "high",
            "The path or parameters contain ../ or %2e%2e, which may read files outside the "
            "web root.",
            "Normalise and allow-list paths on the server side, rejecting any input containing ..",
            "path-traversal",
        )

    if any(signature in combined for signature in _SQLI_SIGNATURES):
        add(
            "Possible SQL injection signature",
            "high",
            "Parameters contain common SQL injection patterns such as union select / or 1=1.",
            "Use parameterised queries (prepared statements) and deploy a WAF.",
            "sqli-signature",
        )

    if any(signature in combined for signature in _XSS_SIGNATURES):
        add(
            "Possible XSS / injection characters",
            "high",
            "Parameters contain <script, onerror= or %00, which may be used for reflected XSS "
            "or truncation.",
            "Escape output (HTML escape) and allow-list validate input.",
            "xss-signature",
        )

    redirect_hits = sorted(set(target.query_params) & _REDIRECT_PARAMS)
    if redirect_hits:
        add(
            f"Open redirect parameter: {', '.join(redirect_hits)}",
            "medium",
            "Such parameters are often abused as phishing hops or to bypass an SSRF allow-list.",
            "Restrict redirect targets to an allow-list of domains instead of using raw user input.",
            "open-redirect",
        )

    if re.search(r"https?%3a%2f%2f", decoded_query):
        add(
            "External URL inside a parameter (SSRF indicator)",
            "medium",
            "The query string contains an absolute URL; if the server fetches it, this may "
            "enable SSRF.",
            "Restrict the network ranges the server may request and block internal addresses "
            "(169.254.169.254 and friends).",
            "ssrf-indicator",
        )

    exec_hits = sorted(set(target.query_params) & _EXEC_PARAMS)
    if exec_hits:
        add(
            f"High-risk parameter name: {', '.join(exec_hits)}",
            "medium",
            "The parameter names suggest file access or command execution; confirm that input "
            "validation is in place.",
            "Allow-list validate file/command related parameters instead of concatenating them "
            "into system calls.",
            "dangerous-param-name",
        )

    secret_hits = sorted(set(target.query_params) & _SECRET_PARAMS)
    if secret_hits:
        add(
            f"Secret-like parameter in the query string: {', '.join(secret_hits)}",
            "high",
            "Secrets in a URL end up in server and proxy access logs, which is sensitive data "
            "exposure.",
            "Use a POST body or an Authorization header, and rotate any leaked credentials.",
            "secret-in-query",
        )

    for needle, (severity, why) in _SENSITIVE_PATHS.items():
        if needle in decoded_path:
            add(
                f"Sensitive endpoint: /{needle.strip('.')}",
                severity,
                why,
                "Restrict source IPs or add an extra authentication layer (VPN / SSO), and keep "
                "the service up to date.",
                f"sensitive-path:{needle}",
            )

    if re.fullmatch(r"\d{1,10}", target.host or "") or re.fullmatch(r"0x[0-9a-f]+", target.host or ""):
        extra = ""
        if re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", target.host or ""):
            extra = " (possibly a decimal/hex encoded IP, often used to bypass filters)"
        add(
            "IP address instead of a domain name",
            "low",
            f"No domain or certificate validation, which is common for scanning activity or "
            f"DNS filter bypass{extra}.",
            "Confirm whether this IP is an expected asset and track it in the asset inventory.",
            "ip-literal-host",
        )

    if "xn--" in (target.host or ""):
        add(
            "Punycode domain (homograph attack risk)",
            "medium",
            "Domains starting with xn-- can look identical to well-known brands and are often "
            "used for phishing.",
            "Display the decoded Unicode domain and verify the source is trustworthy.",
            "punycode-host",
        )

    if not target.is_default_port:
        add(
            f"Non-standard port: {target.port}",
            "info",
            "Services outside 80/443 often lack consistent perimeter protection and monitoring.",
            "Front them with a reverse proxy and restrict sources at the firewall.",
            "non-standard-port",
        )

    if len(decoded_query) > 200:
        add(
            "Unusually long query string",
            "low",
            "Very long parameters may be used to probe parameter pollution or trigger parsing "
            "discrepancies.",
            "Enforce a request length limit and log anomalous requests.",
            "long-query-string",
        )

    if len([segment for segment in decoded_path.split("/") if segment]) >= 5:
        add(
            "Unusually deep path",
            "info",
            "Deep paths are common for traversal probing or leftover backup directories.",
            "Check the web root for paths that should not be publicly reachable.",
            "deep-path",
        )

    if re.search(r"\.(php|asp|aspx|jsp|cgi|pl|sh|bak|old|zip|tar|gz|sql|log)$", decoded_path):
        add(
            "Suspicious file extension",
            "low",
            "The path ends with an executable script or a backup/archive file that may be "
            "requested or downloaded directly.",
            "Do not serve backup files or raw scripts, and block these extensions at the server.",
            "suspicious-file-extension",
        )

    return findings


def score_from_findings(findings: list[dict]) -> int:
    """Convert a finding list into a 0-100 risk score.

    A single issue never maxes out the score (to avoid alarm fatigue); only several
    medium/high findings stacked together approach 100.
    """
    score = 0
    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        score += SEVERITY_WEIGHT.get(severity, 0)
    return max(0, min(score, 100))


def merge_findings(*groups: list[dict]) -> list[dict]:
    """Merge findings from several sources and drop exact duplicates (first one wins)."""
    merged: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for group in groups:
        for finding in group or []:
            key = (
                str(finding.get("title", "")).strip().lower(),
                normalize_severity(finding.get("severity")),
                str(finding.get("rule") or finding.get("source") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(finding)
    return merged


def highest_severity(findings: list[dict]) -> str:
    """Return the most severe level in the list (``info`` for an empty list)."""
    if not findings:
        return "info"
    return max(
        (normalize_severity(finding.get("severity")) for finding in findings),
        key=lambda severity: SEVERITY_RANK.get(severity, 0),
    )

