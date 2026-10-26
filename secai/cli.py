"""SecAI CLI entry point.

One click group plus four subcommands, centralising:

* Global options (``--dry-run`` / ``--json`` / ``--model`` / ``--retries`` ...).
* Mapping exceptions to exit codes so shells / CI can reliably judge the result.
* The ``build_client()`` factory: tests can monkeypatch it to stay fully offline.
"""

from __future__ import annotations

import sys
from typing import Sequence

import click

from secai import __version__
from secai.ai_client import DeepSeekClient
from secai.commands import analyze_log, check_config, cve, scan_url
from secai.commands._shared import AppContext
from secai.exceptions import EXIT_INTERNAL, EXIT_OK, EXIT_USAGE, SecAIError
from secai.render import build_console, print_error

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"], "max_content_width": 100}


def build_client(
    *,
    model: str | None,
    base_url: str | None,
    timeout: float,
    retries: int,
    console,
) -> DeepSeekClient:
    """Create the DeepSeek client.

    It is a separate function (rather than a ``new`` inside the callback) so tests can
    monkeypatch ``secai.cli.build_client`` to inject a fake client,
    keeping every CLI test off the network.
    """

    def on_retry(attempt: int, reason: str, delay: float) -> None:
        console.print(
            f"[yellow]Retry {attempt} (in {delay:.1f}s): {reason}[/yellow]"
        )

    return DeepSeekClient(
        model=model,
        base_url=base_url,
        timeout=timeout,
        max_retries=retries,
        on_retry=on_retry,
    )


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, "--version", "-V", prog_name="secai")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Only print what would be sent to the API without calling it (no API key, works offline for demos)",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Emit results as JSON, handy for CI or other tools",
)
@click.option("--model", default=None, metavar="NAME", help="Model name (defaults to deepseek-chat, override with DEEPSEEK_MODEL)")
@click.option("--base-url", default=None, metavar="URL", help="API base URL (override with DEEPSEEK_BASE_URL)")
@click.option(
    "--timeout",
    type=click.FloatRange(1, 600),
    default=60.0,
    show_default=True,
    help="Timeout for a single API request (seconds)",
)
@click.option(
    "--retries",
    type=click.IntRange(0, 10),
    default=3,
    show_default=True,
    help="Number of retries on failure (exponential backoff; 429 honours Retry-After)",
)
@click.option("-v", "--verbose", is_flag=True, help="Show debug information (the key is masked)")
@click.pass_context
def cli(
    ctx: click.Context,
    dry_run: bool,
    output_json: bool,
    model: str | None,
    base_url: str | None,
    timeout: float,
    retries: int,
    verbose: bool,
) -> None:
    """SecAI - an AI-driven cybersecurity assistant.

    Use DeepSeek to analyse logs, CVEs, configuration files, and URLs, producing structured, readable security conclusions.

    \b
    Commands:
      analyze-log   Analyse a log file and find anomalous behaviour
      cve           Look up CVE details and remediation advice
      check-config  Check firewall / SSH / Nginx and other configuration files
      scan-url      Assess the risk of a URL (purely passive analysis)

    \b
    Environment variables:
      DEEPSEEK_API_KEY   Required (not needed with --dry-run)
      DEEPSEEK_MODEL     Defaults to deepseek-chat
      DEEPSEEK_BASE_URL  Defaults to https://api.deepseek.com
      SECAI_NO_COLOR=1   Force colour output off

    \b
    Option placement:
      Global options go before the command (secai --json scan-url URL);
      --json and --dry-run may also be written after the command (secai scan-url URL --json).

    \b
    Exit codes:
      0 success, 2 bad input, 3 bad configuration, 4 API failure, 10 a finding reached the threshold
    """
    console = build_console()
    # In --json mode stdout must carry exactly one JSON document, so retry notices and other
    # diagnostics go to stderr instead of corrupting the payload.
    diag_console = build_console(stderr=True) if output_json else console
    ctx.obj = AppContext(
        console=console,
        ai=build_client(
            model=model,
            base_url=base_url,
            timeout=timeout,
            retries=retries,
            console=diag_console,
        ),
        dry_run=dry_run,
        output_json=output_json,
        verbose=verbose,
        diag_console=diag_console,
    )


cli.add_command(analyze_log)
cli.add_command(cve)
cli.add_command(check_config)
cli.add_command(scan_url)


def main(argv: Sequence[str] | None = None) -> int:
    """Program entry point: returns the process exit code.

    Using ``standalone_mode=False`` lets us handle exceptions ourselves,
    which is what allows mapping a :class:`secai.exceptions.SecAIError` to its exit code.
    """
    error_console = build_console(stderr=True)
    try:
        result = cli.main(
            args=list(argv) if argv is not None else None,
            prog_name="secai",
            standalone_mode=False,
        )
        return int(result) if isinstance(result, int) else EXIT_OK
    except click.exceptions.Exit as exc:
        return int(exc.exit_code or EXIT_OK)
    except click.UsageError as exc:
        exc.show(file=sys.stderr)
        return EXIT_USAGE
    except click.ClickException as exc:
        exc.show(file=sys.stderr)
        return int(exc.exit_code)
    except click.exceptions.Abort:
        error_console.print("[yellow]Operation aborted.[/yellow]")
        return 130
    except SecAIError as exc:
        print_error(error_console, exc)
        return exc.exit_code
    except BrokenPipeError:  # e.g. `secai ... | head`
        return EXIT_OK
    except KeyboardInterrupt:
        error_console.print("\n[yellow]Cancelled.[/yellow]")
        return 130
    except Exception as exc:  # pragma: no cover - last line of defence against ugly tracebacks
        print_error(
            error_console,
            SecAIError(f"Unexpected error: {type(exc).__name__}: {exc}", hint="Add -v or report an issue"),
        )
        return EXIT_INTERNAL


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
