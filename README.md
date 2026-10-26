# SecAI CLI

> An AI-powered security assistant: use **DeepSeek** to analyse logs, CVEs, config files and URLs, and get structured, readable, CI-friendly security conclusions.

[![CI](https://github.com/Olilee10/secai-cli/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

```console
$ secai analyze-log samples/access.log --fail-on high
$ secai scan-url "http://10.0.0.5/upload.php?file=../../etc/passwd"
$ echo $?     # 10 = a finding reached the threshold
```

---

## Table of contents

- [Features](#features)
- [Installation](#installation)
- [Quick start (no API key needed)](#quick-start-no-api-key-needed)
- [Environment variables](#environment-variables)
- [Commands](#commands)
- [Output format and exit codes](#output-format-and-exit-codes)
- [Docker](#docker)
- [Development and testing](#development-and-testing)
- [Architecture](#architecture)
- [Reliability design](#reliability-design)
- [Security and limitations](#security-and-limitations)

---

## Features

| Feature | Description |
| --- | --- |
| Four practical commands | `analyze-log`, `cve`, `check-config`, `scan-url` |
| Structured output | `--json` emits a **single, complete** JSON document (no tables or progress messages mixed in), ready for `json.loads()` |
| CI-friendly | `--fail-on` lets the tool express its result through the exit code like a linter (`0` pass / `10` finding) |
| Usable without a key | `--dry-run` only prints what would be sent to the API: no quota used, perfect for offline demos |
| Tolerant of AI responses | Three-tier JSON extraction plus a plain-text fallback, so a model that skips JSON does not break everything |
| Network fault tolerance | Exponential backoff retries, honours `Retry-After`, and does not waste quota retrying 401/403/400 |
| Passive analysis | `scan-url` only analyses the URL string you give it and **never** sends a request to the target |
| Zero-network tests | All 149 tests use injected fake clients/sessions, so CI needs no secrets |

## Installation

Requires **Python 3.11+** (dependencies ask for >= 3.10).

```bash
git clone https://github.com/Olilee10/secai-cli.git
cd secai-cli

python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows (PowerShell)
venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp .env.example .env        # Windows: copy .env.example .env
# edit .env and fill in DEEPSEEK_API_KEY=sk-...
```

## Quick start (no API key needed)

```bash
# see which prompt would be sent (no API call)
python secai.py --dry-run analyze-log samples/access.log
python secai.py --dry-run check-config samples/firewall.rules
python secai.py --dry-run cve CVE-2024-1234

# local heuristics only (no AI call at all)
python secai.py scan-url "http://10.0.0.5/x.php?file=../../etc/passwd" --no-ai
```

After setting a key (in `.env` or the environment) you can run real analyses:

```bash
python secai.py analyze-log samples/access.log --fail-on high
python secai.py check-config samples/sshd_config
python secai.py cve CVE-2024-1234
python secai.py scan-url https://example.com/.env
```

You can also run it as a module: `python -m secai --help` (same as `python secai.py --help`).

## Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `DEEPSEEK_API_KEY` | Yes (not needed with `--dry-run`) | — | DeepSeek API key |
| `DEEPSEEK_MODEL` | No | `deepseek-chat` | Model name, override with `--model` |
| `DEEPSEEK_BASE_URL` | No | `https://api.deepseek.com` | API base URL, override with `--base-url` (handy for a self-hosted gateway) |
| `SECAI_NO_COLOR` | No | — | Set to `1` to force colours off (useful when writing to files or CI logs) |

> The key is only read from the environment and is never written to disk; `-v` debug output masks it too.

## Commands

### `analyze-log` — analyse a log file

Finds the genuinely suspicious lines (brute force, SQL injection, path traversal, scanners, privilege escalation, data leaks, C2 callbacks ...),
sends them to the model in batches, and finally summarises them into one report.

```bash
secai analyze-log access.log
secai analyze-log access.log --batch-size 20 --max-lines 500
secai analyze-log auth.log --show-all --fail-on high --json
```

| Option | Default | Description |
| --- | --- | --- |
| `LOG_FILE` | — | Text log file to analyse |
| `--batch-size N` | `12` | Lines per batch sent to the model (smaller is cheaper and less likely to time out) |
| `--max-lines N` | `200` | Maximum lines to analyse (`0` = all) |
| `--show-all` | off | Also show lines the model judged benign |
| `--encoding NAME` | `utf-8` | File encoding |
| `--fail-on LEVEL` | `none` | Exit code `10` when a finding reaches the threshold |
| `--json` / `--dry-run` | off | Same as the global options (may also be written after the command) |


### `check-config` — audit a config file

Looks for dangerous settings in firewall rules, `sshd_config`, Nginx, Docker and similar files (open by default, weak crypto, overly broad permissions ...)
and adds remediation advice.

```bash
secai check-config firewall.rules
secai check-config sshd_config --focus ssh
secai check-config nginx.conf --fail-on medium --json
```

| Option | Default | Description |
| --- | --- | --- |
| `CONFIG_FILE` | — | Path to the config file |
| `--max-bytes N` | `12000` | Maximum bytes sent to the AI; anything beyond is truncated (`truncated: true`) |
| `--focus TOPIC` | — | Focus on a topic, e.g. `ssh`, `tls`, `iptables` |
| `--encoding NAME` | `utf-8` | File encoding |
| `--fail-on LEVEL` | `none` | Exit code `10` when the overall risk level reaches the threshold |

### `cve` — look up CVE details

Uses the model to summarise a CVE's affected scope, attack conditions, severity and remediation, with a disclaimer attached (always defer to NVD / the vendor advisory).

```bash
secai cve CVE-2024-1234
secai cve CVE-2024-1234 --fail-on critical --json
```

| Option | Default | Description |
| --- | --- | --- |
| `CVE_ID` | — | CVE ID (format is validated first; exit code `2` when wrong) |
| `--fail-on LEVEL` | `none` | Exit code `10` when the CVE (or its overall severity) reaches the threshold |

### `scan-url` — URL risk assessment

**Purely passive analysis**: it only parses the URL string you provide (scheme, host, port, path, query, payload shape, suspicious file names ...),
combines local heuristic rules with AI semantic judgement into one score, and labels the source of every finding (`heuristic` / `ai`).

```bash
secai scan-url https://example.com/api/admin
secai scan-url "http://10.0.0.5/x.php?file=../../etc/passwd" --no-ai
secai scan-url https://example.com/.env --fail-on high
```

| Option | Default | Description |
| --- | --- | --- |
| `URL` | — | URL to assess (unsafe schemes such as `javascript:` are rejected) |
| `--no-ai` | off | Run local heuristics only: no AI call and no API key needed |
| `--fail-on LEVEL` | `none` | Exit code `10` when a finding reaches the threshold |

### Global options

Write them **before** the subcommand (`secai --json scan-url ...`); `--json` and `--dry-run` may also be written **after** it (`secai scan-url ... --json`) — both forms are equivalent.

| Option | Default | Description |
| --- | --- | --- |
| `-V, --version` | — | Show the version |
| `-h, --help` | — | Show help |
| `--dry-run` | off | Only print what would be sent to the API: no API call and no key needed |
| `--json` | off | JSON output (a single document, easy to pipe) |
| `--model NAME` | `deepseek-chat` | Model name |
| `--base-url URL` | `https://api.deepseek.com` | API base URL |
| `--timeout SEC` | `60.0` | Per-request timeout (1–600) |
| `--retries N` | `3` | Number of retries on failure (0–10, exponential backoff + `Retry-After`) |
| `-v, --verbose` | off | Show debug information (the key is masked) |


## Output format and exit codes

### Exit codes

| Code | Meaning | Typical situation |
| --- | --- | --- |
| `0` | Success | Analysis finished and `--fail-on` was not reached |
| `1` | Internal error | Unexpected exception (with a hint asking for a report) |
| `2` | Input error | Bad arguments, missing/unreadable file, malformed CVE/URL |
| `3` | Configuration error | `DEEPSEEK_API_KEY` is missing |
| `4` | API failure | Retries exhausted, authentication failure, malformed response |
| `10` | Finding found | `--fail-on` threshold reached (in `--json` mode the full JSON is still printed first) |
| `130` | Interrupted by user | `Ctrl+C` |

### `--json` output

`--json` mode emits **only** one JSON object (no tables, no progress bars, no fallback hints), ready to pipe into `jq` / `python -m json.tool`:

```console
$ secai analyze-log access.log --json | jq '.anomaly_count'
```

Keys per command:

- `analyze-log`: `command`, `file`, `lines_total`, `lines_analyzed`, `batches`, `findings[]`, `anomaly_count`, `dropped_out_of_range_lines`, `summary`, `fallback_batches`, `token_usage`
- `check-config`: `command`, `file`, `config_type`, `truncated`, `parsed`, `risk_level`, `summary`, `findings[]`, `hardening_tips[]`, `raw`, `parse_error`
- `cve`: `command`, `cve_id`, `parsed`, `data`, `raw`, `parse_error`, `disclaimer`
- `scan-url`: `command`, `url`, `host`, `scheme`, `port`, `dry_run`, `no_ai`, `request`, `parsed`, `risk_level`, `risk_score`, `summary`, `findings[]`, `verification_steps[]`, `assumptions[]`, `raw`, `parse_error`

Every element of `findings[]` always contains `severity` (`info`/`low`/`medium`/`high`/`critical`) and `title`; the remaining fields only appear when they have a value: `reason` or `description` (the rationale / explanation), `remediation` (fix advice), `line` (log line number), `source` (`heuristic` local rule / `ai` model judgement), `rule` (local rule name), `type` or `category` (attack type), `location` (position inside the config file).

With `--dry-run --json`, `analyze-log` / `check-config` / `cve` emit `{dry_run, command, endpoint, payload}` (`payload` is the OpenAI-compatible request that would be sent), while `scan-url` emits the full result and puts the request in the `request` field.

Diagnostics never touch that document: retry notices (`Retry 1 (in 1.5s): ...`), `-v` verbose lines, and warnings such as a truncated response are written to **stderr**, so `stdout` stays exactly one JSON object even when retries happen. The same applies to errors: a failure (exit code `4`) leaves `stdout` empty and explains itself on `stderr`.

### CI integration example

```yaml
- name: Security scan
  env:
    DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
    SECAI_NO_COLOR: "1"
  run: |
    python secai.py analyze-log /var/log/nginx/access.log --fail-on high --json | tee report.json
```

```bash
# local rules only, no key needed at all
secai scan-url "$TARGET_URL" --no-ai --fail-on medium --json | jq '.findings | length'
```

## Docker

The image runs as a non-root user (uid 10001) and contains `secai.py`, `secai/` and `samples/`.

```bash
# build
docker build -t secai-cli .

# offline demo (no key needed)
docker run --rm secai-cli --dry-run analyze-log samples/access.log
docker run --rm secai-cli scan-url "https://example.com/.env" --no-ai

# real analysis with a key (the key is only passed via the environment, never baked into the image)
docker run --rm -e DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  -v "$PWD/logs:/data:ro" \
  secai-cli analyze-log /data/access.log --fail-on high --json
```

Docker Compose is even simpler (it reads `.env` automatically and mounts `./samples` as `/data:ro`):

```bash
cp .env.example .env          # fill in DEEPSEEK_API_KEY
docker compose build
docker compose run --rm secai analyze-log /data/access.log --fail-on high
docker compose run --rm secai check-config /data/sshd_config
docker compose run --rm secai scan-url "http://10.0.0.5/x.php?file=../../etc/passwd" --no-ai
```

If the output contains garbled boxes, your terminal does not support UTF-8 or has no TTY; add `--json` or set `SECAI_NO_COLOR=1` to get plain-text / pure JSON output.


## Development and testing

```bash
pip install -r requirements.txt -r requirements-dev.txt

python -m pytest                      # 149 passed (fully offline, no API key needed)
python -m pytest tests/test_cli.py -v  # only the end-to-end CLI tests
python -m pytest -k fail_on            # only the --fail-on cases
```

`pytest.ini` already sets `testpaths = tests`, so plain `pytest` works.

| Test file | Cases | Coverage |
| --- | --- | --- |
| `tests/test_validators.py` | 45 | URL / CVE format validation, severity normalisation, secret masking, config-type guessing |
| `tests/test_cli.py` | 46 | End-to-end through the real `cli.main()`: all 4 commands, exit codes, pure JSON output, `--fail-on` |
| `tests/test_heuristics.py` | 23 | Local URL rules, severity ordering, score calculation, finding merging |
| `tests/test_ai_client.py` | 16 | Retries / backoff, `Retry-After`, error mapping, response parsing (with injected fake session/sleep) |
| `tests/test_parsing.py` | 14 | Three-tier JSON extraction, fenced code blocks, fallback decisions, object / array parsing |

Testing principles: no mock framework is used; everything relies on hand-written `FakeClient` / `FakeSession` / `chat_payload`
(see `tests/conftest.py`), with `secai.cli.build_client` monkeypatched when needed.
Therefore **the tests never touch the network and never consume API quota**.

## Architecture

```text
secai-cli/
├── secai.py                 # thin entry point: sys.exit(main())
├── secai/
│   ├── cli.py               # click group, global options, exception -> exit code
│   ├── ai_client.py         # DeepSeek client (retries, backoff, Retry-After)
│   ├── parsing.py           # three-tier JSON extraction + plain-text fallback
│   ├── validators.py        # input validation, normalisation, secret masking
│   ├── heuristics.py        # local rules and risk scoring (scan-url)
│   ├── render.py            # rich rendering (tables, panels, risk colour scale)
│   ├── prompts.py           # per-command system prompts and JSON schema notes
│   ├── exceptions.py        # exception types <-> exit codes
│   └── commands/            # analyze_log / check_config / cve / scan_url + _shared.py
├── tests/                   # 149 offline tests
├── samples/                 # access.log, firewall.rules, sshd_config
├── Dockerfile / docker-compose.yml / .dockerignore
├── .github/workflows/ci.yml  # 3.11/3.12/3.13 tests + Docker build
└── requirements.txt / requirements-dev.txt / pytest.ini / LICENSE / README.md
```

Design principle: `commands/` only does "build prompt -> call the AI -> render", while every shared behaviour (file reading, dry-run, threshold checks, JSON output) lives in `commands/_shared.py`; the lower-level capabilities (API, parsing, validation, rendering) are independent and individually testable.

## Reliability design

LLMs time out, get rate limited, and return absurd formats. This tool has an explicit answer to each case:

1. **Transport layer**: only `408/409/425/429/5xx` and connection errors / timeouts are retried; `401/403` (key) and `400` (invalid request) fail immediately so quota is not wasted. Backoff is exponential with jitter, and a server-provided `Retry-After` is always honoured (capped at 30 seconds).
2. **Parsing layer**: first look for a ```` ```json ```` code block -> then a direct `json.loads` -> then scan for the first balanced `{...}` / `[...]`; only when all of these fail does it fall back to plain text, flagging `fallback_batches` / `parse_error` in the output instead of pretending success.
3. **Semantic layer**: every finding is normalised — severity only allows five levels, lines with out-of-range numbers are dropped and counted in `dropped_out_of_range_lines`, and missing fields are shown as `—`.
4. **Cost layer**: `--batch-size`, `--max-lines` and `--max-bytes` control how much data is sent; `--dry-run` lets you **inspect the prompt before spending anything**.
5. **Explainability**: every `scan-url` finding labels its source (`heuristic` or `ai`), so local rules and AI judgement can be reviewed separately.

## Security and limitations

- **Read-only**: it only reads the files you specify (or a plain URL string), never modifies anything, and writes nothing beyond the report.
- **`scan-url` makes no network requests**: it only does string and semantic analysis on the URL you give it; it never sends probes or attack traffic to the target. It is not a DAST / vulnerability scanner.
- **Data leaves your machine**: `analyze-log` / `check-config` / `cve` send (possibly truncated) content to the DeepSeek API. Do not analyse content containing personal data, keys or secrets; in enterprise environments you can point `--base-url` at a self-hosted, OpenAI-compatible endpoint.
- **The AI can hallucinate**: treat NVD / vendor advisories as the final authority on a CVE's affected scope and fixed versions (the `cve` command prints a disclaimer). This tool assists judgement; it does not replace professional assessment.
- **`--no-ai` is a fully offline mode**: local heuristics only, zero API calls, suited to sensitive environments or as a first-pass filter.

## License

[MIT License](LICENSE). Only use this tool against systems you are legally authorised to test; unauthorised scanning or testing may be illegal.
