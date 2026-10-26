"""Unit tests for ``secai.parsing``, focused on the many ways an AI response can be malformed."""

from __future__ import annotations

import json

import pytest

from secai.parsing import clean_text, extract_json, parse_findings, parse_object


def test_clean_text_collapses_blank_lines():
    assert clean_text("a\r\n\r\n\r\n\r\nb\r\n") == "a\n\nb"


def test_extract_json_from_fenced_block():
    text = 'Here is the result:\n```json\n{"findings": [{"title": "test"}]}\n```\nHope that helps'
    assert extract_json(text) == {"findings": [{"title": "test"}]}


def test_extract_json_ignores_braces_inside_strings():
    text = 'Preamble {"note": "a string with } and {", "findings": []} epilogue'
    data = extract_json(text)
    assert data == {"note": "a string with } and {", "findings": []}


def test_extract_json_returns_none_for_prose():
    assert extract_json("This is explanatory prose without any JSON") is None


def test_extract_json_handles_top_level_array():
    assert extract_json("The result is [1, 2, 3]") == [1, 2, 3]


def test_parse_findings_normalizes_fields():
    payload = {
        "findings": [
            {"line": "12", "type": "brute_force", "severity": "HIGH!", "reason": "the same IP hit 401 repeatedly"},
        ],
        "summary": "Overall normal",
    }
    result = parse_findings(json.dumps(payload))

    assert result.ok is True
    assert result.used_fallback is False
    finding, = result.findings
    assert finding["line"] == 12
    assert finding["severity"] == "high"
    assert finding["title"] == "brute_force"
    assert finding["source"] == "ai"


def test_parse_findings_accepts_single_object_without_list():
    text = '{"line": 3, "severity": "medium", "reason": "suspicious User-Agent"}'
    result = parse_findings(text)

    assert result.used_fallback is False
    assert result.findings[0]["severity"] == "medium"
    assert result.findings[0]["title"] == "Unnamed finding"


def test_parse_findings_treats_bare_array_as_findings():
    text = '[{"title": "scanner", "severity": "low"}]'
    result = parse_findings(text)
    assert [item["title"] for item in result.findings] == ["scanner"]


def test_parse_findings_finds_nested_list():
    text = '{"result": {"anomalies": [{"title": "data leak", "severity": "critical"}]}}'
    result = parse_findings(text)
    assert result.findings[0]["severity"] == "critical"


def test_parse_findings_falls_back_on_prose():
    result = parse_findings("I think this log looks normal, nothing anomalous was found.")

    assert result.used_fallback is True
    assert result.findings == []
    assert result.error
    assert "normal" in result.raw


def test_parse_findings_falls_back_on_empty_findings_list():
    result = parse_findings('{"findings": [], "summary": "All normal"}')

    assert result.ok is False  # no usable findings -> let the caller decide how to render
    assert result.data == {"findings": [], "summary": "All normal"}


def test_parse_object_requires_fields():
    result = parse_object('{"foo": "bar"}', required=("severity", "description"))
    assert result.used_fallback is True
    assert "required fields" in (result.error or "")


def test_parse_object_accepts_nested_findings():
    text = '{"risk_level": "high", "findings": [{"title": "SQLi", "severity": "high"}]}'
    result = parse_object(text, required=("risk_level",))

    assert result.ok is True
    assert result.data["risk_level"] == "high"
    assert result.findings[0]["title"] == "SQLi"


def test_parse_object_unwraps_single_element_array():
    result = parse_object('[{"title": "X", "severity": "low"}]', required=("title",))
    assert result.data == {"title": "X", "severity": "low"}
