"""Unit tests for ``secai.validators``."""

from __future__ import annotations

import pytest

from secai.exceptions import EXIT_USAGE, InvalidInputError
from secai.validators import (
    guess_config_type,
    normalize_cve_id,
    normalize_severity,
    normalize_url,
    redact_secret,
    severity_rank,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("critical", "critical"),
        ("CRITICAL", "critical"),
        (" Crit ", "critical"),
        ("P1", "critical"),
        ("severe", "critical"),
        ("Moderate", "medium"),
        ("p3", "medium"),
        ("important", "high"),
        ("informational", "info"),
        ("none", "info"),
        ("HIGH!", "high"),
    ],
)
def test_normalize_severity_aliases(raw, expected):
    assert normalize_severity(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "???", 42, "urgent"])
def test_normalize_severity_unknown(raw):
    assert normalize_severity(raw) == "unknown"
    assert severity_rank(raw) == 0


def test_severity_rank_is_ordered():
    ranks = [severity_rank(value) for value in ("info", "low", "medium", "high", "critical")]
    assert ranks == sorted(ranks)
    assert severity_rank("critical") > severity_rank("high") > severity_rank("none")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CVE-2024-1234", "CVE-2024-1234"),
        ("cve-2021-44228", "CVE-2021-44228"),
        ("CVE 2024 1234", "CVE-2024-1234"),
        ("cve_2023_0001", "CVE-2023-0001"),
        ("Please look at CVE-2019-0708 here", "CVE-2019-0708"),
    ],
)
def test_normalize_cve_id_accepts_variants(raw, expected):
    assert normalize_cve_id(raw) == expected


@pytest.mark.parametrize("raw", ["", "CVE-2024", "CVE-24-1234", "MS17-010", "CVE-2024-12"])
def test_normalize_cve_id_rejects_bad_input(raw):
    with pytest.raises(InvalidInputError) as excinfo:
        normalize_cve_id(raw)
    assert excinfo.value.exit_code == EXIT_USAGE
    assert "CVE" in excinfo.value.message


def test_normalize_url_adds_scheme_and_strips_fragment():
    target = normalize_url("example.com/api/admin#token=abc")
    assert target.normalized == "https://example.com/api/admin"
    assert target.scheme == "https"
    assert target.host == "example.com"
    assert target.port == 443
    assert target.is_default_port is True


def test_normalize_url_keeps_query_params():
    target = normalize_url("http://10.0.0.5:8080/x.php?file=../../etc/passwd&q=1")
    assert target.scheme == "http"
    assert target.port == 8080
    assert target.has_query is True
    assert target.query_params["file"] == ["../../etc/passwd"]
    assert target.is_default_port is False


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "ftp://example.com/x", "file:///etc/passwd", "https://", "https://host:abc/"],
)
def test_normalize_url_rejects_bad_input(raw):
    with pytest.raises(InvalidInputError) as excinfo:
        normalize_url(raw)
    assert excinfo.value.exit_code == EXIT_USAGE


@pytest.mark.parametrize(
    ("filename", "content", "expected"),
    [
        ("nginx.conf", "server {\n  listen 80;\n  location / { }\n}", "nginx"),
        ("sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes", "ssh"),
        ("firewall.rules", "*filter\n-A INPUT -j ACCEPT\nCOMMIT", "firewall"),
        ("docker-compose.yml", "services:\n  web:\n    image: nginx", "docker"),
        ("deployment.yaml", "apiVersion: apps/v1\nkind: Deployment", "kubernetes"),
        ("unknown.txt", "just some text", "generic"),
    ],
)
def test_guess_config_type(filename, content, expected):
    assert guess_config_type(filename, content) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("", "(not set)"), (None, "(not set)"), ("short", "*****"), ("sk-abcdefghijklmnop", "sk-a******mnop")],
)
def test_redact_secret(raw, expected):
    assert redact_secret(raw) == expected
