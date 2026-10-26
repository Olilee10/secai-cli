"""Input validation and normalisation.

All "user input -> canonical form" logic is deliberately kept here so the CLI
layer only has to present results, and tests can run completely offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse, urlunparse

from secai.exceptions import InvalidInputError

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CVE_LOOSE_PATTERN = re.compile(r"CVE[\s\-_]*(\d{4})[\s\-_]*(\d{4,})", re.IGNORECASE)

#: Severity is always normalised to these six values, so the AI cannot return free
#: text such as "HIGH!" or "moderate".
SEVERITIES = ("critical", "high", "medium", "low", "info")

#: Severity ranking (the larger the number, the more severe); used for the
#: --fail-on threshold comparison and for sorting.
SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "unknown": 0,
}

#: severity -> rich style (colour + bold).
SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold cyan",
    "info": "bold blue",
    "unknown": "bold magenta",
}

_SEVERITY_ALIASES = {
    "crit": "critical",
    "critical": "critical",
    "severe": "critical",
    "p1": "critical",
    "p2": "high",
    "high": "high",
    "important": "high",
    "p3": "medium",
    "medium": "medium",
    "moderate": "medium",
    "med": "medium",
    "p4": "low",
    "low": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "none": "info",
}


def normalize_severity(value: object) -> str:
    """Reduce any spelling of a severity to one of :data:`SEVERITIES`.

    The AI often returns variations such as ``"Moderate"``, ``"HIGH "`` or
    ``"P1"``; they are all unified here so sorting, colouring and threshold
    comparisons stay reliable.
    """
    if value is None:
        return "unknown"
    text = str(value).strip().lower()
    if not text:
        return "unknown"
    text = re.sub(r"[^a-z0-9]", "", text)
    return _SEVERITY_ALIASES.get(text, "unknown")


def severity_rank(value: object) -> int:
    """Return a comparable rank for a severity."""
    return SEVERITY_RANK.get(normalize_severity(value), 0)


def normalize_cve_id(raw: str) -> str:
    """Validate and normalise a CVE ID.

    Accepts spellings such as ``cve-2024-1234`` or ``CVE 2024 1234`` and always
    returns ``CVE-2024-1234``.
    """
    candidate = (raw or "").strip()
    if CVE_PATTERN.match(candidate):
        return candidate.upper()
    loose = _CVE_LOOSE_PATTERN.search(candidate)
    if loose:
        return f"CVE-{loose.group(1)}-{loose.group(2)}"
    raise InvalidInputError(
        f"'{raw}' is not a valid CVE ID",
        hint="The correct format is e.g. CVE-2024-1234 (CVE-year-at least four digits)",
    )


@dataclass
class UrlTarget:
    """A validated URL together with its parsed components."""

    original: str
    normalized: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    query_params: dict[str, list[str]] = field(default_factory=dict)

    @property
    def is_default_port(self) -> bool:
        return self.port in (80, 443)

    @property
    def has_query(self) -> bool:
        return bool(self.query)


def normalize_url(raw: str) -> UrlTarget:
    """Validate a URL and fill in the scheme.

    Only http/https are accepted; when the scheme is missing ``https://`` is assumed.
    """
    candidate = (raw or "").strip()
    if not candidate:
        raise InvalidInputError(
            "The URL must not be empty", hint="For example https://example.com/api/admin"
        )

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in ("http", "https"):
        raise InvalidInputError(
            f"Only http/https is supported, got '{parsed.scheme}'",
            hint="The scanner does not support schemes such as file:// or ftp://",
        )
    if not parsed.hostname:
        raise InvalidInputError(
            f"'{raw}' is missing a host name", hint="For example https://example.com/api"
        )

    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:  # for example https://host:abc/
        raise InvalidInputError(f"Invalid port: {exc}") from exc

    normalized = urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",  # the fragment does not affect server behaviour, drop it
        )
    )
    return UrlTarget(
        original=raw.strip(),
        normalized=normalized,
        scheme=parsed.scheme.lower(),
        host=(parsed.hostname or "").lower(),
        port=port,
        path=parsed.path or "/",
        query=parsed.query,
        query_params=parse_qs(parsed.query, keep_blank_values=True),
    )


def guess_config_type(filename: str, content: str) -> str:
    """Guess the config file type from the file name and content, so the prompt can be sharper."""
    name = (filename or "").lower()
    head = content[:4000].lower()

    if "nginx" in name or "server {" in head and "location" in head:
        return "nginx"
    if "sshd" in name or "ssh" in name or "permitrootlogin" in head:
        return "ssh"
    if "iptables" in name or "firewall" in name or "nftables" in name or "chain " in head:
        return "firewall"
    if "docker" in name or "compose" in name:
        return "docker"
    if "kube" in name or "apiVersion:" in content[:2000]:
        return "kubernetes"
    if "listen" in head and "directive" in head:
        return "webserver"
    return "generic"


def redact_secret(value: str | None, keep: int = 4) -> str:
    """Mask a sensitive string (API key), keeping only a few characters for debugging."""
    if not value:
        return "(not set)"
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * 6}{value[-keep:]}"
