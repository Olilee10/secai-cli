"""Shared pytest configuration and test doubles.

The project deliberately avoids mock libraries; every double is a minimal hand-written class
(``FakeClient`` / ``FakeSession`` / ``FakeResponse``), keeping dependencies clean and readable.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Sequence

import pytest
from click.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # make secai importable regardless of the current cwd
    sys.path.insert(0, str(ROOT))

from secai.ai_client import AIResponse  # noqa: E402  (sys.path must be patched first)


def chat_payload(
    content: str,
    *,
    model: str = "deepseek-chat",
    usage: dict[str, int] | None = None,
    finish_reason: str = "stop",
) -> dict[str, Any]:
    """Build an OpenAI/DeepSeek compatible chat/completions response."""
    return {
        "id": "chatcmpl-test",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": finish_reason}],
        "usage": usage if usage is not None else {"prompt_tokens": 100, "completion_tokens": 20},
    }


class FakeResponse:
    """A fake requests.Response."""

    def __init__(
        self,
        status_code: int = 200,
        payload: Any = None,
        *,
        text: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        if text is not None:
            self.text = text
        else:
            self.text = json.dumps(payload) if payload is not None else ""

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("the response is not JSON")
        return self._payload


class FakeSession:
    """Return the scheduled responses in order (may be exceptions) and record every call."""

    def __init__(self, responses: Sequence[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError("FakeSession has no scheduled responses left")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeClient:
    """A fake DeepSeekClient: same interface as the real client but never touches the network."""

    def __init__(
        self,
        responses: Sequence[Any] | None = None,
        *,
        model: str = "fake-model",
        api_key: str = "sk-fake",
    ) -> None:
        self.responses = list(responses or [])
        self.calls: list[dict[str, str]] = []
        self.model = model
        self.api_key = api_key
        self.base_url = "https://fake.local"

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/v1/chat/completions"

    def describe(self) -> str:
        return f"model={self.model} endpoint={self.endpoint} api_key={self.api_key[:4]}******"

    def build_payload(self, system_prompt: str, user_input: str, **overrides: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_input},
            ],
            "temperature": 0.1,
            "stream": False,
        }
        if overrides.get("json_mode"):
            payload["response_format"] = {"type": "json_object"}
        return payload

    def complete(
        self,
        system_prompt: str,
        user_input: str,
        *,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> AIResponse:
        self.calls.append({"system_prompt": system_prompt, "user_input": user_input})
        if not self.responses:
            raise AssertionError("FakeClient has no scheduled responses left")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, AIResponse):
            return item
        return AIResponse(
            text=str(item),
            model=self.model,
            usage={"prompt_tokens": 100, "completion_tokens": 20},
            elapsed=0.01,
        )


@pytest.fixture
def runner() -> CliRunner:
    """click test runner (output is captured and never reaches the terminal)."""
    return CliRunner()


@pytest.fixture
def fake_ai(monkeypatch: pytest.MonkeyPatch):
    """Install a fake AI client: after ``fake_ai(['{...}'])`` no command touches the network."""
    from secai import cli as cli_module

    def install(responses: Sequence[Any] | None = None, **kwargs: Any) -> FakeClient:
        client = FakeClient(responses, **kwargs)
        monkeypatch.setattr(cli_module, "build_client", lambda **_ignored: client)
        return client

    return install
