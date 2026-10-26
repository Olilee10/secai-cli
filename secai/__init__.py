"""SecAI - an LLM-powered command line security analysis assistant.

Module layout::

    secai.cli          CLI interface (click group, global options, exit code mapping)
    secai.ai_client    DeepSeek API client (retries, backoff, rate limiting)
    secai.parsing      AI response parsing (JSON extraction + plain text fallback)
    secai.validators   Input validation and normalisation (CVE / URL / severity)
    secai.heuristics   Local risk heuristics that do not need an API
    secai.render       rich terminal output
    secai.prompts      System prompts for every command
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
