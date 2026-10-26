"""The SecAI CLI command collection."""

from __future__ import annotations

from secai.commands.analyze_log import analyze_log
from secai.commands.check_config import check_config
from secai.commands.cve import cve
from secai.commands.scan_url import scan_url

__all__ = ["analyze_log", "check_config", "cve", "scan_url"]
