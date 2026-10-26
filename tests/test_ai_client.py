"""Unit tests for ``secai.ai_client``.

Everything uses an injected ``FakeSession`` / ``sleep``, so no real request is ever sent
and no backoff delay is actually awaited.
"""

from __future__ import annotations

import pytest
import requests

from secai.ai_client import (
    API_KEY_ENV,
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    AIResponse,
    DeepSeekClient,
)
from secai.exceptions import (
    EXIT_API,
    EXIT_CONFIG,
    ApiError,
    AuthError,
    ConfigError,
    InvalidAIResponseError,
    RateLimitError,
)

from conftest import FakeResponse, FakeSession, chat_payload


def build_client(session, **kwargs) -> DeepSeekClient:
    """Create a client with an injected fake session / sleep (tests never wait or connect)."""
    kwargs.setdefault("api_key", "sk-test")
    kwargs.setdefault("jitter", 0.0)
    kwargs.setdefault("sleep", lambda _seconds: None)
    return DeepSeekClient(session=session, **kwargs)


def test_defaults_come_from_environment(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_MODEL", raising=False)
    monkeypatch.delenv("DEEPSEEK_BASE_URL", raising=False)
    client = DeepSeekClient(api_key="sk-x", session=FakeSession([]))

    assert client.model == DEFAULT_MODEL
    assert client.base_url == DEFAULT_BASE_URL
    assert client.endpoint == f"{DEFAULT_BASE_URL}/v1/chat/completions"

    monkeypatch.setenv("DEEPSEEK_MODEL", "deepseek-reasoner")
    monkeypatch.setenv("DEEPSEEK_BASE_URL", "https://proxy.local/")
    overridden = DeepSeekClient(api_key="sk-x", session=FakeSession([]))

    assert overridden.model == "deepseek-reasoner"
    assert overridden.endpoint == "https://proxy.local/v1/chat/completions"


def test_describe_redacts_api_key():
    client = DeepSeekClient(api_key="sk-1234567890abcdef", session=FakeSession([]))

    described = client.describe()

    assert "sk-1234567890abcdef" not in described
    assert "sk-1" in described


def test_missing_api_key_raises_config_error(monkeypatch):
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    client = DeepSeekClient(api_key="", session=FakeSession([]))

    with pytest.raises(ConfigError) as excinfo:
        client.complete("sys", "user")

    assert excinfo.value.exit_code == EXIT_CONFIG
    assert API_KEY_ENV in excinfo.value.message


def test_complete_success_builds_request_and_parses_response():
    session = FakeSession([FakeResponse(200, chat_payload('{"findings": []}'))])
    client = build_client(session)

    response = client.complete("system prompt", "user input", json_mode=True)

    assert isinstance(response, AIResponse)
    assert response.text == '{"findings": []}'
    assert response.model == "deepseek-chat"
    assert response.prompt_tokens == 100
    assert response.completion_tokens == 20
    assert response.attempts == 1
    assert response.finish_reason == "stop"
    assert response.request_id == "chatcmpl-test"
    assert response.elapsed >= 0

    url, kwargs = session.calls[0]
    assert url.endswith("/v1/chat/completions")
    assert kwargs["headers"]["Authorization"] == "Bearer sk-test"
    assert kwargs["json"]["response_format"] == {"type": "json_object"}
    assert kwargs["json"]["messages"][0]["content"] == "system prompt"
    assert kwargs["json"]["messages"][1]["content"] == "user input"
    assert kwargs["timeout"] == 60.0


def test_json_mode_can_be_disabled():
    session = FakeSession([FakeResponse(200, chat_payload("plain text"))])
    client = build_client(session)

    client.complete("s", "u", json_mode=False)

    assert "response_format" not in session.calls[0][1]["json"]


def test_retries_server_error_then_succeeds():
    session = FakeSession(
        [
            FakeResponse(503, {"error": "busy"}, text="busy"),
            FakeResponse(200, chat_payload("ok")),
        ]
    )
    sleeps: list[float] = []
    client = build_client(session, max_retries=2, sleep=sleeps.append, backoff_factor=2.0)
    retries: list[tuple[int, str, float]] = []
    client.on_retry = lambda attempt, reason, delay: retries.append((attempt, reason, delay))

    response = client.complete("s", "u")

    assert response.text == "ok"
    assert response.attempts == 2
    assert len(session.calls) == 2
    assert sleeps == [1.0]  # 2 ** (attempt - 1)
    assert retries and retries[0][0] == 1


def test_gives_up_after_max_retries():
    session = FakeSession([FakeResponse(500, text="boom") for _ in range(3)])
    sleeps: list[float] = []
    client = build_client(session, max_retries=2, sleep=sleeps.append, backoff_factor=1.0)

    with pytest.raises(ApiError) as excinfo:
        client.complete("s", "u")

    assert excinfo.value.exit_code == EXIT_API
    assert "retried 2 times" in excinfo.value.message
    assert len(session.calls) == 3
    assert sleeps == [1.0, 1.0]


def test_auth_error_is_not_retried():
    session = FakeSession([FakeResponse(401, text="invalid api key")])
    client = build_client(session, max_retries=3)

    with pytest.raises(AuthError) as excinfo:
        client.complete("s", "u")

    assert excinfo.value.exit_code == EXIT_API
    assert len(session.calls) == 1
    assert "401" in excinfo.value.message


def test_rate_limit_respects_retry_after_header():
    session = FakeSession(
        [
            FakeResponse(429, text="slow down", headers={"Retry-After": "2.5"}),
            FakeResponse(429, text="slow down", headers={"Retry-After": "2.5"}),
        ]
    )
    sleeps: list[float] = []
    client = build_client(session, max_retries=1, sleep=sleeps.append, backoff_factor=5.0)

    with pytest.raises(RateLimitError) as excinfo:
        client.complete("s", "u")

    assert sleeps == [2.5]  # prefer Retry-After over exponential backoff
    assert "429" in excinfo.value.message


def test_retry_after_is_capped_by_max_backoff():
    session = FakeSession(
        [
            FakeResponse(429, text="slow down", headers={"Retry-After": "600"}),
            FakeResponse(429, text="slow down", headers={"Retry-After": "600"}),
        ]
    )
    sleeps: list[float] = []
    client = build_client(session, max_retries=1, sleep=sleeps.append, max_backoff=10.0)

    with pytest.raises(RateLimitError):
        client.complete("s", "u")

    assert sleeps == [10.0]


def test_timeout_and_connection_errors_are_retried():
    session = FakeSession(
        [
            requests.exceptions.Timeout("too slow"),
            requests.exceptions.ConnectionError("no route"),
            FakeResponse(200, chat_payload("late ok")),
        ]
    )
    client = build_client(session, max_retries=3)

    response = client.complete("s", "u")

    assert response.text == "late ok"
    assert response.attempts == 3


def test_client_error_is_not_retried():
    session = FakeSession([FakeResponse(400, text="bad request")])
    client = build_client(session, max_retries=3)

    with pytest.raises(ApiError) as excinfo:
        client.complete("s", "u")

    assert "400" in excinfo.value.message
    assert len(session.calls) == 1


def test_non_json_body_raises_invalid_response():
    session = FakeSession([FakeResponse(200, None, text="<html>gateway error</html>")])
    client = build_client(session)

    with pytest.raises(InvalidAIResponseError) as excinfo:
        client.complete("s", "u")

    assert "gateway error" in (excinfo.value.hint or "")


def test_payload_error_field_raises_api_error():
    session = FakeSession([FakeResponse(200, {"error": {"message": "quota exceeded"}})])
    client = build_client(session)

    with pytest.raises(ApiError) as excinfo:
        client.complete("s", "u")

    assert "quota exceeded" in excinfo.value.message


def test_missing_choices_raises_invalid_response():
    session = FakeSession([FakeResponse(200, {"id": "x", "choices": []})])
    client = build_client(session)

    with pytest.raises(InvalidAIResponseError):
        client.complete("s", "u")


def test_usage_missing_is_tolerated():
    session = FakeSession([FakeResponse(200, {"choices": [{"message": {"content": "hi"}}]})])
    client = build_client(session)

    response = client.complete("s", "u")

    assert response.text == "hi"
    assert response.prompt_tokens is None
    assert response.completion_tokens is None

