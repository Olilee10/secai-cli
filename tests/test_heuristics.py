"""Unit tests for ``secai.heuristics`` (pure local rules, no network needed)."""

from __future__ import annotations

import pytest

from secai.heuristics import (
    highest_severity,
    merge_findings,
    score_from_findings,
    url_heuristics,
)
from secai.validators import normalize_url


def rules(target_url: str) -> set[str]:
    return {finding["rule"] for finding in url_heuristics(normalize_url(target_url))}


def test_plain_http_is_flagged():
    assert "transport-plaintext" in rules("http://example.com/")


def test_https_is_not_flagged_for_transport():
    assert "transport-plaintext" not in rules("https://example.com/")


def test_path_traversal_detected():
    findings = url_heuristics(normalize_url("http://10.0.0.5/x.php?file=../../etc/passwd"))
    assert "path-traversal" in {item["rule"] for item in findings}
    assert all(item["source"] == "heuristic" for item in findings)


def test_percent_encoded_traversal_detected():
    assert "path-traversal" in rules("https://example.com/download?file=%2e%2e%2f%2e%2e%2fetc/passwd")


def test_sql_injection_signature_detected():
    assert "sqli-signature" in rules("https://example.com/search?q=1%27%20OR%201%3D1--")


def test_xss_signature_detected():
    assert "xss-signature" in rules("https://example.com/search?q=<script>alert(1)</script>")


def test_open_redirect_parameter_detected():
    assert "open-redirect" in rules("https://example.com/login?next=https://evil.example.com")


def test_secret_in_query_detected():
    findings = url_heuristics(normalize_url("https://example.com/cb?token=abcdef123456"))
    assert "secret-in-query" in {item["rule"] for item in findings}


def test_sensitive_path_detected():
    assert "sensitive-path:.env" in rules("https://example.com/.env")


def test_non_standard_port_detected():
    findings = url_heuristics(normalize_url("https://example.com:8443/admin"))
    assert "non-standard-port" in {item["rule"] for item in findings}


def test_credentials_in_url_detected():
    assert "credentials-in-url" in rules("https://user:pass@example.com/admin")


@pytest.mark.parametrize("host", ["3232235525", "0xc0a80005"])
def test_decimal_or_hex_ip_literal_host_detected(host):
    assert "ip-literal-host" in rules(f"https://{host}/admin")


def test_dotted_ipv4_host_is_not_treated_as_encoded_ip():
    # The current rules only cover IPs encoded in decimal / hex form (often used to bypass filters);
    # ordinary dotted IPs are handled by other asset management mechanisms.
    assert "ip-literal-host" not in rules("https://10.0.0.5/admin")


def test_clean_url_has_no_high_findings():
    findings = url_heuristics(normalize_url("https://shop.example.com/products/42"))
    assert score_from_findings(findings) < 40
    assert highest_severity(findings) in ("info", "low")


def test_score_from_findings_is_capped_at_100():
    findings = [{"severity": "critical"} for _ in range(5)]
    assert score_from_findings(findings) == 100


def test_score_from_findings_empty_is_zero():
    assert score_from_findings([]) == 0


def test_merge_findings_drops_duplicates_and_keeps_order():
    first = [{"title": "A", "severity": "high", "rule": "r1", "source": "ai"}]
    second = [
        {"title": "a", "severity": "HIGH", "rule": "r1", "source": "heuristic"},
        {"title": "B", "severity": "low", "rule": "r2", "source": "heuristic"},
    ]
    merged = merge_findings(first, second)

    assert [item["title"] for item in merged] == ["A", "B"]
    assert merged[0]["source"] == "ai"


def test_merge_findings_handles_none_groups():
    assert merge_findings(None, []) == []


@pytest.mark.parametrize(
    ("findings", "expected"),
    [
        ([], "info"),
        ([{"severity": "low"}], "low"),
        ([{"severity": "low"}, {"severity": "critical"}], "critical"),
        ([{"severity": "HIGH!"}, {"severity": "moderate"}], "high"),
    ],
)
def test_highest_severity(findings, expected):
    assert highest_severity(findings) == expected
