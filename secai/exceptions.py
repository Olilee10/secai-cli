"""Exception types and exit codes for SecAI.

Exit code design (so the tool can be used from CI like a linter)::

    0   EXIT_OK        Success, and no risk reached the threshold
    1   EXIT_INTERNAL  Unexpected internal error
    2   EXIT_USAGE     Invalid user input (arguments, file name, CVE format, URL format)
    3   EXIT_CONFIG    Configuration error (for example a missing DEEPSEEK_API_KEY)
    4   EXIT_API       The AI API call failed (retries exhausted, malformed response)
    10  EXIT_FINDINGS  Analysis succeeded, but a finding reached the --fail-on threshold
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_API = 4
EXIT_FINDINGS = 10


class SecAIError(Exception):
    """Base class for every "expected" error.

    ``cli.main()`` catches this type, prints an error panel with rich,
    and uses ``exit_code`` as the process exit code.
    """

    exit_code = EXIT_INTERNAL
    title = "Error"

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:  # pragma: no cover - presentation only
        return self.message


class ConfigError(SecAIError):
    """The environment is incomplete, for example no API key is set."""

    exit_code = EXIT_CONFIG
    title = "Configuration error"


class InvalidInputError(SecAIError):
    """The user input is invalid, for example a malformed CVE ID."""

    exit_code = EXIT_USAGE
    title = "Invalid input"


class FileReadError(SecAIError):
    """The file exists but cannot be read (permissions, encoding, it is a directory...)."""

    exit_code = EXIT_USAGE
    title = "Failed to read file"


class ApiError(SecAIError):
    """Communication with the AI service failed."""

    exit_code = EXIT_API
    title = "API error"


class AuthError(ApiError):
    """The key is invalid or lacks permission (not retried)."""

    title = "Authentication failed"


class RateLimitError(ApiError):
    """HTTP 429 that still failed after retrying."""

    title = "Rate limit reached"


class InvalidAIResponseError(ApiError):
    """The AI response has an unexpected structure and cannot be recovered."""

    title = "Unexpected AI response format"
