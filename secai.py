#!/usr/bin/env python3
"""Entry point for SecAI CLI.

Usage::

    python secai.py analyze-log samples/access.log
    python secai.py cve CVE-2024-1234
    python secai.py check-config samples/firewall.rules
    python secai.py scan-url https://example.com/api/admin

It can also be run as a module: ``python -m secai``.
"""

from __future__ import annotations

import sys

from secai.cli import main

if __name__ == "__main__":
    sys.exit(main())
