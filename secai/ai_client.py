"""DeepSeek API client.

This module is the concrete answer to the premise that "the AI is unreliable". It provides:

* **Exponential backoff retries**: timeouts, connection errors, HTTP 429 and 5xx are retried.
* **Retry-After support**: when rate limited, the server's requested delay is honoured
  (capped by ``max_backoff``).
* **Errors that are not retried**: 401/403 (key problems) and 400 (invalid request) fail
  immediately, so quota is not wasted.
* **Structured errors**: every failure becomes an exception from :mod:`secai.exceptions`,
  so the CLI can map it to an exit code.
* **Testability**: ``session`` and ``sleep`` are injectable, so tests never need the network.
"""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import requests

from secai.exceptions import (
    ApiError,
    AuthError,
    ConfigError,
    InvalidAIResponseError,
    RateLimitError,
)
from secai.validators import redact_secret

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"
API_KEY_ENV = "DEEPSEEK_API_KEY"

#: HTTP status codes worth retrying
RETRYABLE_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504})

RetryHook = Callable[[int, str, float], None]


@dataclass
class AIResponse:
    """The result of one successful API call."""

    text: str
    model: str
    attempts: int = 1
    finish_reason: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    request_id: str | None = None
    elapsed: float = 0.0

    @property
    def prompt_tokens(self) -> int | None:
        value = self.usage.get("prompt_tokens")
        return int(value) if isinstance(value, (int, float)) else None

    @property
    def completion_tokens(self) -> int | None:
        value = self.usage.get("completion_tokens")
        return int(value) if isinstance(value, (int, float)) else None


class DeepSeekClient:
    """A minimal DeepSeek Chat Completions client (OpenAI compatible interface)."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 60.0,
        max_retries: int = 3,
        temperature: float = 0.1,
        max_tokens: int | None = None,
        backoff_factor: float = 1.5,
        max_backoff: float = 30.0,
        jitter: float = 0.25,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
        on_retry: RetryHook | None = None,
    ) -> None:
        self.api_key = (api_key if api_key is not None else os.getenv(API_KEY_ENV) or "").strip()
        base = base_url or os.getenv("DEEPSEEK_BASE_URL") or DEFAULT_BASE_URL
        self.base_url = base.rstrip("/")
        self.model = model or os.getenv("DEEPSEEK_MODEL") or DEFAULT_MODEL
        self.timeout = float(timeout)
        self.max_retries = max(0, int(max_retries))
        self.temperature = float(temperature)
        self.max_tokens = max_tokens
        self.backoff_factor = float(backoff_factor)
        self.max_backoff = float(max_backoff)
        self.jitter = float(jitter)
        self.session = session if session is not None else requests.Session()
        self.sleep = sleep
        self.on_retry = on_retry

    # ------------------------------------------------------------------ public API

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/v1/chat/completions"

    def describe(self) -> str:
        """Return a safely printable configuration summary (the key is masked)."""
        return (
            f"model={self.model} endpoint={self.endpoint} "
            f"timeout={self.timeout:.0f}s retries={self.max_retries} "
            f"api_key={redact_secret(self.api_key)}"
        )

    def build_payload(self, system_prompt: str, user_input: str, **overrides: Any) -> dict[str, Any]:
        """Build the chat/completions request body (``--dry-run`` prints exactly this)."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_input},
            ],
            "temperature": overrides.get("temperature", self.temperature),
            "stream": False,
        }
        max_tokens = overrides.get("max_tokens", self.max_tokens)
        if max_tokens:
            payload["max_tokens"] = int(max_tokens)
        if overrides.get("json_mode"):
            payload["response_format"] = {"type": "json_object"}
        return payload

    def complete(
        self,
        system_prompt: str,
        user_input: str,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> AIResponse:
        """Send one chat request, including retries and rate limiting handling.

        :raises ConfigError: no API key configured.
        :raises AuthError: 401 / 403 (not retried).
        :raises RateLimitError: 429 that persisted after all retries.
        :raises ApiError: any other API or network failure.
        """
        if not self.api_key:
            raise ConfigError(
                f"The {API_KEY_ENV} environment variable is not set",
                hint=(
                    "Linux/macOS: export DEEPSEEK_API_KEY=sk-xxx\n"
                    "Windows PowerShell: $env:DEEPSEEK_API_KEY='sk-xxx'\n"
                    "Or copy .env.example and load the settings from it"
                ),
            )

        payload = self.build_payload(
            system_prompt,
            user_input,
            temperature=self.temperature if temperature is None else temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
        )
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        started = time.monotonic()
        last_error: ApiError | None = None

        for attempt in range(1, self.max_retries + 2):
            retry_after: float | None = None
            try:
                response = self.session.post(
                    self.endpoint, headers=headers, json=payload, timeout=self.timeout
                )
            except requests.exceptions.Timeout as exc:
                last_error = ApiError(f"API request timed out (>{self.timeout:.0f}s)", hint=str(exc))
            except requests.exceptions.SSLError as exc:
                last_error = ApiError("TLS connection failed", hint=str(exc))
            except requests.exceptions.RequestException as exc:
                last_error = ApiError(
                    "Unable to connect to the API", hint=f"{type(exc).__name__}: {exc}"
                )
            else:
                status = response.status_code
                if status in (401, 403):
                    raise AuthError(
                        f"API authentication failed (HTTP {status})",
                        hint=f"Check whether {API_KEY_ENV} is valid: {_body_snippet(response)}",
                    )
                if status == 429:
                    retry_after = _parse_retry_after(response)
                    last_error = RateLimitError(
                        "API rate limit hit (HTTP 429)",
                        hint="Lower the request rate, or reduce --batch-size / --max-lines",
                    )
                elif status in RETRYABLE_STATUS:
                    last_error = ApiError(
                        f"Transient API error (HTTP {status})", hint=_body_snippet(response)
                    )
                elif status >= 400:
                    raise ApiError(
                        f"API request failed (HTTP {status})", hint=_body_snippet(response)
                    )
                else:
                    result = _decode_response(response)
                    result.attempts = attempt
                    result.elapsed = time.monotonic() - started
                    return result

            if attempt > self.max_retries:
                break

            delay = self._backoff_delay(attempt, retry_after)
            if self.on_retry is not None:
                self.on_retry(attempt, str(last_error), delay)
            self.sleep(delay)

        assert last_error is not None  # always set on the failure path; success returns earlier
        last_error.message = f"{last_error.message} (retried {self.max_retries} times)"
        if last_error.hint is None:
            last_error.hint = "Check the network, or raise --retries to retry more often"
        raise last_error

    def _backoff_delay(self, attempt: int, retry_after: float | None) -> float:
        """Compute the delay: prefer Retry-After, otherwise exponential backoff plus jitter."""
        if retry_after is not None:
            return min(max(retry_after, 0.0), self.max_backoff)
        delay = self.backoff_factor ** (attempt - 1)
        if self.jitter:
            delay += random.uniform(0.0, self.jitter)
        return min(delay, self.max_backoff)


def _parse_retry_after(response: requests.Response) -> float | None:
    """Parse the ``Retry-After`` header (both seconds and an HTTP date are supported)."""
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return float(str(raw).strip())
    except (TypeError, ValueError):
        pass
    try:
        from email.utils import parsedate_to_datetime

        target = parsedate_to_datetime(str(raw))
        if target is None:
            return None
        import datetime as _dt

        now = _dt.datetime.now(target.tzinfo)
        return max((target - now).total_seconds(), 0.0)
    except (TypeError, ValueError):
        return None


def _body_snippet(response: requests.Response, limit: int = 200) -> str:
    """Extract a short snippet of the response body as an error hint (avoid dumping whole HTML)."""
    try:
        text = response.text or ""
    except Exception:  # pragma: no cover - defensive fallback
        return ""
    text = " ".join(text.split())
    return text[:limit] + ("…" if len(text) > limit else "")


def _decode_response(response: requests.Response) -> AIResponse:
    """Turn a successful HTTP response into an :class:`AIResponse`."""
    try:
        payload = response.json()
    except ValueError as exc:
        raise InvalidAIResponseError(
            "The API response is not valid JSON", hint=_body_snippet(response)
        ) from exc

    if not isinstance(payload, dict):
        raise InvalidAIResponseError("Unexpected API response structure", hint=str(type(payload)))

    error = payload.get("error")
    if error:
        message = error.get("message") if isinstance(error, dict) else str(error)
        raise ApiError(f"The API returned an error: {message}")

    choices = payload.get("choices") or []
    if not choices:
        raise InvalidAIResponseError(
            "The API response has no 'choices' field",
            hint="The model name may be wrong, or the account quota is exhausted",
        )

    message = choices[0].get("message") or {}
    content = message.get("content")
    if content is None:
        raise InvalidAIResponseError("The API response 'content' is empty")
    if not isinstance(content, str):
        content = str(content)

    usage = payload.get("usage") or {}
    return AIResponse(
        text=content.strip(),
        model=str(payload.get("model") or DEFAULT_MODEL),
        finish_reason=choices[0].get("finish_reason"),
        usage=usage if isinstance(usage, dict) else {},
        request_id=payload.get("id"),
    )

