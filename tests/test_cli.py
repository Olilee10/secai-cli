"""End-to-end CLI tests.

Principles:

* Always call ``secai.cli.main()`` (the real user entry point), which also exercises exit-code mapping.
* The AI is always replaced by :class:`tests.conftest.FakeClient` (the ``fake_ai`` fixture); nothing touches the network.
* The ``--json`` output must be a "single, complete" JSON document; tests prove it with a direct ``json.loads``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from secai import __version__
from secai import cli as cli_module
from secai.ai_client import DeepSeekClient
from secai.exceptions import (
    EXIT_API,
    EXIT_CONFIG,
    EXIT_FINDINGS,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_USAGE,
    ApiError,
)

from conftest import FakeResponse, FakeSession, chat_payload


def run(capsys: pytest.CaptureFixture, *args: str) -> tuple[int, str]:
    """Run the CLI and return ``(exit code, stdout+stderr)``."""
    code = cli_module.main(list(args))
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def run_json(capsys: pytest.CaptureFixture, *args: str) -> tuple[int, dict[str, Any]]:
    """Run the CLI and parse the ``--json`` output (which must be pure JSON)."""
    code, output = run(capsys, *args)
    return code, json.loads(output)


def write(path: Path, text: str) -> Path:
    """Write a test file (UTF-8, with newlines)."""
    path.write_text(text, encoding="utf-8")
    return path


LOG_TEXT = (
    "10.0.0.1 - - [01/Jan/2024:00:00:01] \"GET /index.html HTTP/1.1\" 200 512\n"
    "10.0.0.9 - - [01/Jan/2024:00:00:02] \"POST /login HTTP/1.1\" 401 128\n"
    "10.0.0.9 - - [01/Jan/2024:00:00:03] \"POST /login HTTP/1.1\" 401 128\n"
    "10.0.0.9 - - [01/Jan/2024:00:00:04] \"POST /login HTTP/1.1\" 401 128\n"
    "10.0.0.9 - - [01/Jan/2024:00:00:05] \"POST /login HTTP/1.1\" 401 128\n"
)

LOG_FINDING = {
    "line": 2,
    "severity": "high",
    "title": "probable brute force",
    "reason": "repeated login failures from the same source",
    "is_anomaly": True,
}


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    return write(tmp_path / "access.log", LOG_TEXT)


# --------------------------------------------------------------------------- #
# Basic interface
# --------------------------------------------------------------------------- #
def test_help_lists_every_command(capsys):
    code, output = run(capsys, "--help")

    assert code == EXIT_OK
    for name in ("analyze-log", "check-config", "cve", "scan-url"):
        assert name in output


def test_version_option(capsys):
    code, output = run(capsys, "--version")

    assert code == EXIT_OK
    assert __version__ in output


def test_no_arguments_prints_usage_with_usage_exit_code(capsys):
    code, output = run(capsys)

    assert code == EXIT_USAGE
    assert "Usage" in output


def test_unknown_command_is_a_usage_error(capsys):
    code, output = run(capsys, "no-such-command")

    assert code == EXIT_USAGE
    assert "no-such-command" in output


# --------------------------------------------------------------------------- #
# analyze-log
# --------------------------------------------------------------------------- #
def test_analyze_log_dry_run_needs_no_api_key(capsys, monkeypatch, log_file):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    code, output = run(capsys, "--dry-run", "analyze-log", str(log_file))

    assert code == EXIT_OK
    assert "dry-run" in output
    assert "you will get a real analysis" in output


def test_analyze_log_dry_run_json_payload(capsys, monkeypatch, log_file):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    code, payload = run_json(capsys, "--dry-run", "--json", "analyze-log", str(log_file))

    assert code == EXIT_OK
    assert payload["dry_run"] is True
    assert payload["command"].startswith("analyze-log")
    assert payload["endpoint"].endswith("/v1/chat/completions")
    assert "messages" in payload["payload"]


def test_analyze_log_reports_findings(capsys, fake_ai, log_file):
    fake_ai([json.dumps({"findings": [LOG_FINDING], "summary": "login failures concentrated on 10.0.0.9"})])

    code, payload = run_json(
        capsys, "--json", "analyze-log", str(log_file), "--batch-size", "5"
    )

    assert code == EXIT_OK
    assert payload["anomaly_count"] == 1
    assert payload["findings"][0]["line"] == 2
    assert payload["findings"][0]["severity"] == "high"
    assert payload["dropped_out_of_range_lines"] == 0
    assert payload["token_usage"]["calls"] == 1
    assert payload["fallback_batches"] == 0


def test_analyze_log_drops_hallucinated_line_numbers(capsys, fake_ai, log_file):
    fake_ai([json.dumps({"findings": [dict(LOG_FINDING, line=4242)]})])

    code, payload = run_json(capsys, "--json", "analyze-log", str(log_file))

    assert code == EXIT_OK
    assert payload["anomaly_count"] == 0
    assert payload["dropped_out_of_range_lines"] == 1
    assert payload["findings"] == []


def test_analyze_log_splits_into_batches(capsys, fake_ai, log_file):
    client = fake_ai([json.dumps({"findings": []}) for _ in range(3)])

    code, payload = run_json(
        capsys, "--json", "analyze-log", str(log_file), "--batch-size", "2"
    )

    assert code == EXIT_OK
    assert payload["batches"] == 3
    assert payload["token_usage"]["calls"] == 3
    assert len(client.calls) == 3
    # the second batch starts at original line 3, and every line carries its real line number to the AI
    assert client.calls[1]["user_input"].startswith("3: ")
    assert "2: " in client.calls[0]["user_input"]


def test_analyze_log_max_lines_limits_input(capsys, fake_ai, log_file):
    fake_ai([json.dumps({"findings": []})])

    code, payload = run_json(
        capsys, "--json", "analyze-log", str(log_file), "--max-lines", "2"
    )

    assert code == EXIT_OK
    assert payload["lines_total"] == 5
    assert payload["lines_analyzed"] == 2
    assert payload["batches"] == 1
    # a legitimate empty findings list is not a parse failure (it must not be misreported as plain-text mode)
    assert payload["fallback_batches"] == 0


def test_analyze_log_json_output_stays_pure_when_fail_on_triggers(capsys, fake_ai, log_file):
    fake_ai([json.dumps({"findings": [LOG_FINDING]})])

    code, payload = run_json(
        capsys, "--json", "analyze-log", str(log_file), "--fail-on", "high"
    )

    assert code == EXIT_FINDINGS
    assert payload["anomaly_count"] == 1


def test_analyze_log_fail_on_prints_threshold_message(capsys, fake_ai, log_file):
    fake_ai([json.dumps({"findings": [LOG_FINDING]})])

    code, output = run(capsys, "analyze-log", str(log_file), "--fail-on", "medium")

    assert code == EXIT_FINDINGS
    assert "Threshold reached" in output
    assert "exiting with" in output


def test_analyze_log_fail_on_below_threshold_succeeds(capsys, fake_ai, log_file):
    fake_ai([json.dumps({"findings": [dict(LOG_FINDING, severity="low")]})])

    code, _ = run(capsys, "analyze-log", str(log_file), "--fail-on", "high")

    assert code == EXIT_OK


def test_analyze_log_falls_back_to_plain_text(capsys, fake_ai, log_file):
    prose = "I think line 2 looks like brute force; consider blocking the source IP."
    fake_ai([prose, prose])

    code, output = run(capsys, "analyze-log", str(log_file))

    assert code == EXIT_OK
    assert "plain-text mode" in output
    assert "line 2 looks like brute force" in output

    code, payload = run_json(capsys, "--json", "analyze-log", str(log_file))
    assert code == EXIT_OK
    assert payload["fallback_batches"] == 1
    assert payload["anomaly_count"] == 0


def test_analyze_log_hides_benign_lines_unless_show_all(capsys, fake_ai, log_file):
    benign = json.dumps({"findings": [dict(LOG_FINDING, is_anomaly=False)]})
    fake_ai([benign, benign])

    code, payload = run_json(capsys, "--json", "analyze-log", str(log_file))
    assert code == EXIT_OK
    assert payload["findings"] == []

    code, payload = run_json(
        capsys, "--json", "analyze-log", str(log_file), "--show-all"
    )
    assert code == EXIT_OK
    assert len(payload["findings"]) == 1
    assert payload["anomaly_count"] == 0


def test_analyze_log_empty_file_exits_with_usage_code(capsys, tmp_path):
    empty = write(tmp_path / "empty.log", "   \n\n")

    code, output = run(capsys, "analyze-log", str(empty))

    assert code == EXIT_USAGE
    assert "is empty" in output


def test_analyze_log_missing_file_is_rejected(capsys, tmp_path):
    code, output = run(capsys, "analyze-log", str(tmp_path / "nope.log"))

    assert code == EXIT_USAGE
    assert "nope.log" in output


def test_analyze_log_requires_api_key(capsys, monkeypatch, log_file):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    code, output = run(capsys, "analyze-log", str(log_file))

    assert code == EXIT_CONFIG
    assert "DEEPSEEK_API_KEY" in output


# --------------------------------------------------------------------------- #
# cve
# --------------------------------------------------------------------------- #
CVE_JSON = json.dumps(
    {
        "cve_id": "CVE-2024-1234",
        "title": "Remote Code Execution in Example Service",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-502",
        "affected_systems": ["Example Service 1.0-1.4"],
        "exploitability": "PoC is publicly available",
        "description": "Unauthenticated deserialization allows remote code execution.",
        "remediation": "Upgrade to 1.5 and disable unsafe deserialization.",
        "uncertain_fields": ["affected_systems"],
    },
    ensure_ascii=False,
)


def test_cve_json_output(capsys, fake_ai):
    fake_ai([CVE_JSON])

    code, payload = run_json(capsys, "--json", "cve", "CVE-2024-1234")

    assert code == EXIT_OK
    assert payload["cve_id"] == "CVE-2024-1234"
    assert payload["parsed"] is True
    assert payload["data"]["severity"] == "CRITICAL"
    assert payload["disclaimer"]


def test_cve_normalizes_loose_input(capsys, fake_ai):
    client = fake_ai([CVE_JSON])

    code, payload = run_json(capsys, "--json", "cve", "please look at cve 2019 0708")

    assert code == EXIT_OK
    assert payload["cve_id"] == "CVE-2019-0708"
    assert client.calls[0]["user_input"] == "CVE-2019-0708"


def test_cve_fail_on_critical(capsys, fake_ai):
    fake_ai([CVE_JSON])

    code, output = run(capsys, "cve", "CVE-2024-1234", "--fail-on", "critical")

    assert code == EXIT_FINDINGS
    assert "Threshold reached" in output


def test_cve_plain_text_response_uses_fallback_panel(capsys, fake_ai):
    fake_ai(["This vulnerability is very serious; please upgrade as soon as possible."])

    code, output = run(capsys, "cve", "CVE-2024-1234")

    assert code == EXIT_OK
    assert "parsable" in output
    assert "This vulnerability is very serious" in output
    assert "NVD" in output


def test_cve_invalid_id_is_a_usage_error(capsys):
    code, output = run(capsys, "cve", "not-a-cve")

    assert code == EXIT_USAGE
    assert "CVE" in output


def test_cve_dry_run_payload(capsys, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    code, payload = run_json(capsys, "--dry-run", "--json", "cve", "cve-2024-1234")

    assert code == EXIT_OK
    assert payload["payload"]["messages"][1]["content"] == "CVE-2024-1234"
    assert payload["payload"]["response_format"] == {"type": "json_object"}


# --------------------------------------------------------------------------- #
# Flag position: writing them after the subcommand works too (same as the global options)
# --------------------------------------------------------------------------- #
def test_json_flag_can_follow_subcommand(capsys):
    code, payload = run_json(
        capsys, "scan-url", "https://example.com/.env", "--no-ai", "--json"
    )

    assert code == EXIT_OK
    assert payload["risk_score"] > 0


def test_json_flag_can_follow_subcommand_for_file_commands(capsys, fake_ai, log_file):
    fake_ai([json.dumps({"findings": [LOG_FINDING]})])

    code, payload = run_json(capsys, "analyze-log", str(log_file), "--json")

    assert code == EXIT_OK
    assert payload["anomaly_count"] == 1


def test_dry_run_flag_can_follow_subcommand(capsys, monkeypatch, log_file):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    code, payload = run_json(
        capsys, "analyze-log", str(log_file), "--dry-run", "--json"
    )

    assert code == EXIT_OK
    assert payload["dry_run"] is True


def test_fail_on_still_works_with_local_json_flag(capsys, fake_ai, log_file):
    fake_ai([json.dumps({"findings": [LOG_FINDING]})])

    code, payload = run_json(
        capsys, "analyze-log", str(log_file), "--json", "--fail-on", "high"
    )

    assert code == EXIT_FINDINGS
    assert payload["anomaly_count"] == 1


# --------------------------------------------------------------------------- #
# Exit code mapping
# --------------------------------------------------------------------------- #
def test_verbose_prints_client_info_without_leaking_key(capsys, fake_ai):
    fake_ai([CVE_JSON], api_key="sk-supersecretvalue")

    code, output = run(capsys, "-v", "cve", "CVE-2024-1234")

    assert code == EXIT_OK
    assert "sk-supersecretvalue" not in output
    assert "sk-s" in output


# --------------------------------------------------------------------------- #
# --json purity: diagnostics must never corrupt the machine-readable output
# --------------------------------------------------------------------------- #
def install_real_client(monkeypatch: pytest.MonkeyPatch, responses: list[Any]) -> None:
    """Run the real :class:`DeepSeekClient` behind the CLI, but with a fake HTTP session."""

    def factory(**kwargs: Any):
        kwargs.setdefault("api_key", "sk-test")
        kwargs.setdefault("jitter", 0.0)
        return DeepSeekClient(session=FakeSession(responses), sleep=lambda _delay: None, **kwargs)

    monkeypatch.setattr(cli_module, "DeepSeekClient", factory)


def test_json_mode_keeps_stdout_clean_when_the_client_retries(capsys, monkeypatch):
    install_real_client(
        monkeypatch,
        [
            FakeResponse(status_code=500, payload={"error": "upstream failure"}),
            FakeResponse(payload=chat_payload(CVE_JSON)),
        ],
    )

    code = cli_module.main(["--json", "--retries", "1", "cve", "CVE-2024-1234"])
    captured = capsys.readouterr()

    assert code == EXIT_OK
    assert json.loads(captured.out)["parsed"] is True  # stdout is still one JSON document
    assert "Retry" in captured.err                     # the notice is not lost, just moved
    assert "Retry" not in captured.out


def test_retry_notice_stays_on_stdout_without_json(capsys, monkeypatch):
    install_real_client(
        monkeypatch,
        [
            FakeResponse(status_code=500, payload={"error": "upstream failure"}),
            FakeResponse(payload=chat_payload(CVE_JSON)),
        ],
    )

    code = cli_module.main(["--retries", "1", "cve", "CVE-2024-1234"])
    captured = capsys.readouterr()

    assert code == EXIT_OK
    assert "Retry" in captured.out


def test_verbose_diagnostics_go_to_stderr_in_json_mode(capsys, monkeypatch):
    install_real_client(monkeypatch, [FakeResponse(payload=chat_payload(CVE_JSON))])

    code = cli_module.main(["--json", "-v", "cve", "CVE-2024-1234"])
    captured = capsys.readouterr()

    assert code == EXIT_OK
    assert json.loads(captured.out)["parsed"] is True
    assert "[verbose]" in captured.err
    assert "[verbose]" not in captured.out


def test_truncated_response_warning_goes_to_stderr_in_json_mode(capsys, monkeypatch):
    install_real_client(
        monkeypatch, [FakeResponse(payload=chat_payload(CVE_JSON, finish_reason="length"))]
    )

    code = cli_module.main(["--json", "cve", "CVE-2024-1234"])
    captured = capsys.readouterr()

    assert code == EXIT_OK
    assert json.loads(captured.out)["parsed"] is True
    assert "cut off" in captured.err
    assert "cut off" not in captured.out


def test_json_mode_leaves_stdout_empty_when_the_api_fails(capsys, monkeypatch):
    install_real_client(monkeypatch, [FakeResponse(status_code=401, payload={"error": "bad key"})])

    code = cli_module.main(["--json", "cve", "CVE-2024-1234"])
    captured = capsys.readouterr()

    assert code == EXIT_API
    assert captured.out.strip() == ""
    assert "authentication" in captured.err.lower()


def test_api_error_maps_to_api_exit_code(capsys, fake_ai):
    fake_ai([ApiError("the upstream API keeps failing")])

    code, output = run(capsys, "cve", "CVE-2024-1234")

    assert code == EXIT_API
    assert "the upstream API keeps failing" in output


def test_unexpected_error_maps_to_internal_exit_code(capsys, monkeypatch):
    from secai import cli as cli_module

    def boom(**_ignored):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli_module, "build_client", boom)

    code, output = run(capsys, "cve", "CVE-2024-1234")

    assert code == EXIT_INTERNAL
    assert "Unexpected error" in output
    assert "kaboom" in output


# --------------------------------------------------------------------------- #
# check-config
# --------------------------------------------------------------------------- #
CHECK_CONFIG_JSON = json.dumps(
    {
        "risk_level": "high",
        "summary": "The SSH configuration allows direct root login and uses password authentication.",
        "findings": [
            {
                "title": "Direct root login allowed",
                "severity": "high",
                "location": "PermitRootLogin yes",
                "description": "Attackers can brute force root directly.",
                "remediation": "Change it to PermitRootLogin prohibit-password.",
            }
        ],
        "hardening_tips": ["deploy fail2ban", "switch to key-based authentication"],
    },
    ensure_ascii=False,
)


@pytest.fixture
def sshd_config(tmp_path: Path) -> Path:
    return write(
        tmp_path / "sshd_config",
        "PermitRootLogin yes\nPasswordAuthentication yes\nPort 22\n",
    )


def test_check_config_json_output(capsys, fake_ai, sshd_config):
    fake_ai([CHECK_CONFIG_JSON])

    code, payload = run_json(capsys, "--json", "check-config", str(sshd_config))

    assert code == EXIT_OK
    assert payload["config_type"] == "ssh"
    assert payload["risk_level"] == "high"
    assert payload["truncated"] is False
    assert payload["findings"][0]["severity"] == "high"
    assert "location: " in payload["findings"][0]["description"]
    assert payload["hardening_tips"] == ["deploy fail2ban", "switch to key-based authentication"]


def test_check_config_fail_on_uses_risk_level(capsys, fake_ai, sshd_config):
    fake_ai([json.dumps({"risk_level": "high", "summary": "x", "findings": []})])

    code, output = run(capsys, "check-config", str(sshd_config), "--fail-on", "medium")

    assert code == EXIT_FINDINGS
    assert "Threshold reached" in output


def test_check_config_truncates_large_file(capsys, fake_ai, tmp_path):
    big = write(tmp_path / "firewall.rules", "*filter\n" + "-A INPUT -j ACCEPT\n" * 500)
    fake_ai([json.dumps({"risk_level": "low", "findings": [], "summary": "ok"})])

    code, payload = run_json(
        capsys, "--json", "check-config", str(big), "--max-bytes", "1000"
    )

    assert code == EXIT_OK
    assert payload["config_type"] == "firewall"
    assert payload["truncated"] is True


def test_check_config_focus_is_passed_to_prompt(capsys, fake_ai, sshd_config):
    client = fake_ai([CHECK_CONFIG_JSON])

    run(capsys, "check-config", str(sshd_config), "--focus", "tls")

    assert "tls" in client.calls[0]["system_prompt"]


def test_check_config_missing_file_is_rejected(capsys, tmp_path):
    code, output = run(capsys, "check-config", str(tmp_path / "missing.conf"))

    assert code == EXIT_USAGE
    assert "missing.conf" in output


def test_check_config_dry_run_does_not_call_ai(capsys, monkeypatch, sshd_config):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    code, output = run(capsys, "--dry-run", "check-config", str(sshd_config))

    assert code == EXIT_OK
    assert "dry-run" in output


# --------------------------------------------------------------------------- #
# scan-url
# --------------------------------------------------------------------------- #
def test_scan_url_no_ai_is_fully_offline(capsys, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    code, payload = run_json(
        capsys,
        "--json",
        "scan-url",
        "http://10.0.0.5/x.php?file=../../etc/passwd",
        "--no-ai",
    )

    assert code == EXIT_OK
    assert payload["no_ai"] is True
    assert payload["dry_run"] is False
    assert payload["risk_score"] > 0
    rules = {item["rule"] for item in payload["findings"]}
    assert "path-traversal" in rules
    assert "transport-plaintext" in rules
    assert {item["source"] for item in payload["findings"]} == {"heuristic"}


def test_scan_url_no_ai_clean_target_scores_zero(capsys):
    code, payload = run_json(
        capsys, "--json", "scan-url", "https://shop.example.com/products/42", "--no-ai"
    )

    assert code == EXIT_OK
    assert payload["findings"] == []
    assert payload["risk_score"] == 0
    assert payload["risk_level"] == "info"


def test_scan_url_no_ai_fail_on(capsys):
    code, output = run(
        capsys, "scan-url", "https://example.com/.env", "--no-ai", "--fail-on", "high"
    )

    assert code == EXIT_FINDINGS
    assert "Threshold reached" in output


def test_scan_url_merges_ai_and_heuristic_findings(capsys, fake_ai):
    fake_ai(
        [
            json.dumps(
                {
                    "risk_level": "medium",
                    "risk_score": 55,
                    "summary": "The admin interface still needs its authorization mechanism confirmed.",
                    "findings": [
                        {
                            "title": "Unauthorized access risk",
                            "severity": "medium",
                            "description": "The AI judges that this endpoint may lack an authorization check.",
                        }
                    ],
                    "verification_steps": ["open it in an incognito window and see whether it redirects to a login page"],
                    "assumptions": ["assumes no WAF is deployed"],
                },
                ensure_ascii=False,
            )
        ]
    )

    code, payload = run_json(capsys, "--json", "scan-url", "https://example.com/admin")

    assert code == EXIT_OK
    assert payload["risk_score"] == 55
    assert {item["source"] for item in payload["findings"]} == {"ai", "heuristic"}
    assert payload["summary"] == "The admin interface still needs its authorization mechanism confirmed."
    assert payload["verification_steps"]
    assert payload["assumptions"]


@pytest.mark.parametrize(
    ("url", "needle"),
    [
        ("", "URL"),
        ("https://", "host name"),
        ("ftp://example.com/x", "Only http/https is supported"),
        ("https://example.com:abc/", "Invalid port"),
    ],
)
def test_scan_url_invalid_url_is_a_usage_error(capsys, url, needle):
    code, output = run(capsys, "scan-url", url)

    assert code == EXIT_USAGE
    assert needle in output


def test_scan_url_dry_run_keeps_local_findings(capsys, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    code, payload = run_json(
        capsys, "--dry-run", "--json", "scan-url", "http://example.com/.git/config"
    )

    assert code == EXIT_OK
    assert payload["dry_run"] is True
    assert {item["source"] for item in payload["findings"]} == {"heuristic"}
    # even in dry-run it still shows "what would be sent", and the whole output stays a single JSON document
    assert payload["request"]["messages"][1]["content"] == "http://example.com/.git/config"



