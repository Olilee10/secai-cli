"""AI response parsing: turn unstable natural language output into usable structure.

Design premise: **LLM output format is unreliable**. The same prompt may return:

1. Clean JSON: ``{"findings": [...]}``
2. Wrapped in markdown: ```json ... ```
3. Prose around it: ``Here is the analysis: {...} hope this helps``
4. Prose that is not JSON at all
5. A JSON array instead of an object

Strategy: try three extraction methods in order; if all fail, degrade to "plain text mode"
(``ParseResult.used_fallback is True``) and the CLI prints the raw text instead of crashing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from secai.validators import normalize_severity

#: A ```json ... ``` or ``` ... ``` block
_FENCED_BLOCK = re.compile(r"```[ \t]*(?:json|JSON)?[ \t]*\r?\n?(.*?)```", re.DOTALL)

#: Collapse redundant blank lines
_MULTI_BLANK_LINE = re.compile(r"\n{3,}")


@dataclass
class ParseResult:
    """The parsing result.

    :param data: the parsed structure (dict / list); may be ``None`` in fallback mode.
    :param raw: the cleaned raw AI response text.
    :param findings: the normalised finding list (empty in fallback mode).
    :param used_fallback: whether parsing degraded to plain text mode.
    :param error: why parsing failed (``None`` on success).
    """

    raw: str
    data: Any = None
    findings: list[dict] = field(default_factory=list)
    used_fallback: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return not self.used_fallback


def clean_text(text: str) -> str:
    """Normalise line endings and redundant blank lines so the plain text fallback looks decent."""
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    return _MULTI_BLANK_LINE.sub("\n\n", text).strip()


def iter_json_candidates(text: str) -> Iterator[str]:
    """Yield every possible JSON substring, starting from the outermost balanced brackets.

    A scanner is used instead of a regex so ``{`` / ``}`` inside strings and escape
    sequences are handled correctly.
    """
    for match in _FENCED_BLOCK.finditer(text or ""):
        block = match.group(1).strip()
        if block:
            yield block

    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        while start != -1:
            depth = 0
            in_string = False
            escaped = False
            for index in range(start, len(text)):
                char = text[index]
                if in_string:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == '"':
                        in_string = False
                    continue
                if char == '"':
                    in_string = True
                elif char == opener:
                    depth += 1
                elif char == closer:
                    depth -= 1
                    if depth == 0:
                        yield text[start : index + 1]
                        break
            start = text.find(opener, start + 1)


def extract_json(text: str, *, max_candidates: int = 25) -> Any | None:
    """Extract the first parsable JSON value from arbitrary text; ``None`` if there is none."""
    for index, candidate in enumerate(iter_json_candidates(text)):
        if index >= max_candidates:
            break
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
    # Last chance: the whole text is itself JSON (e.g. a bare number or bare string)
    try:
        return json.loads((text or "").strip())
    except (json.JSONDecodeError, ValueError):
        return None


def _first_list(data: Any, keys: tuple[str, ...]) -> list[Any] | None:
    """Find the first list field in an object (including one nesting level)."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
        for value in data.values():  # nested: {"result": {"findings": [...]}}
            if isinstance(value, dict):
                nested = _first_list(value, keys)
                if nested is not None:
                    return nested
    return None


def _coerce_int(value: Any) -> int | None:
    """Best-effort conversion of ``"3"`` / ``3.0`` / ``None`` to int."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _normalize_finding(item: Any, *, default_source: str) -> dict | None:
    """Normalise a single finding into fixed fields, filling defaults for missing ones."""
    if isinstance(item, str):
        item = {"title": item}
    if not isinstance(item, dict):
        return None

    finding = dict(item)
    title = (
        finding.get("title")
        or finding.get("type")
        or finding.get("name")
        or finding.get("category")
        or finding.get("cve_id")
        or "Unnamed finding"
    )
    finding["title"] = str(title).strip()
    finding["severity"] = normalize_severity(
        finding.get("severity") or finding.get("risk") or finding.get("risk_level")
    )
    finding["source"] = str(finding.get("source") or default_source)
    finding["line"] = _coerce_int(finding.get("line") or finding.get("line_no"))
    return finding


def _looks_like_single_finding(data: dict) -> bool:
    """Decide whether a lone object is actually one "finding" (the AI forgot the array)."""
    keys = {str(key).lower() for key in data}
    return bool(
        keys
        & {
            "is_anomaly",
            "type",
            "reason",
            "severity",
            "description",
            "remediation",
            "advice",
            "risk_level",
            "risk_score",
        }
    )


def parse_findings(
    text: str,
    *,
    list_keys: tuple[str, ...] = ("findings", "issues", "results", "anomalies"),
    default_source: str = "ai",
) -> ParseResult:
    """Parse an AI response that contains a "findings" list.

    Tried in order: the fields named in ``list_keys`` -> a single object -> a top-level array.
    If all fail it degrades to plain text mode (no exception, the caller decides how to present it).
    """
    raw = text or ""
    cleaned = clean_text(raw)
    data = extract_json(raw)

    findings: list[dict] = []
    if data is not None:
        items = _first_list(data, list_keys)
        if items is None and isinstance(data, dict) and _looks_like_single_finding(data):
            items = [data]
        if items is not None:
            for item in items:
                finding = _normalize_finding(item, default_source=default_source)
                if finding is not None:
                    findings.append(finding)

    if findings:
        return ParseResult(raw=raw, data=data, findings=findings)

    return ParseResult(
        raw=cleaned,
        data=data,
        findings=[],
        used_fallback=True,
        error="No usable structured finding list was found in the response",
    )


def parse_object(
    text: str,
    *,
    required: tuple[str, ...] = (),
    default_source: str = "ai",
) -> ParseResult:
    """Parse an AI response that is a single object (e.g. CVE details, a config audit result).

    :param required: at least one of these fields must be present, otherwise parsing is
        considered failed and falls back.
    """
    raw = text or ""
    cleaned = clean_text(raw)
    data = extract_json(raw)

    if isinstance(data, list) and data and isinstance(data[0], dict):
        data = data[0]

    if isinstance(data, dict) and data:
        if required and not any(key in data for key in required):
            return ParseResult(
                raw=cleaned,
                data=data,
                used_fallback=True,
                error=f"The JSON object is missing required fields: {', '.join(required)}",
            )
        findings: list[dict] = []
        for item in _first_list(data, ("findings", "issues", "results")) or []:
            finding = _normalize_finding(item, default_source=default_source)
            if finding is not None:
                findings.append(finding)
        return ParseResult(raw=raw, data=data, findings=findings)

    return ParseResult(
        raw=cleaned,
        data=None,
        used_fallback=True,
        error="The response is not a valid JSON object",
    )


__all__ = [
    "ParseResult",
    "clean_text",
    "extract_json",
    "iter_json_candidates",
    "parse_findings",
    "parse_object",
]
