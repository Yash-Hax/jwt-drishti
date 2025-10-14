import sys
import json
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .analyzer import analyze_token, load_token_from_file, verify_token_with_key, verify_with_jwks

console = Console()

# Rating priority order
RATING_ORDER = {"low": 0, "medium": 1, "high": 2}


# =============================
# Helper functions
# =============================

def _print_text_result(result: dict):
    """Pretty-print result using rich panels and tables."""
    alg = result.get("alg", "unknown")
    verification = result.get("verification")
    warnings = result.get("warnings", [])
    claims = result.get("claims", {}) or {}
    rating = result.get("rating", "low")

    # Header panel
    header_lines = [f"[bold]Algorithm:[/bold] {alg}"]
    if verification is not None:
        verified = verification.get("verified", False)
        header_lines.append(f"[bold]Verified:[/bold] {verified}")
    console.print(Panel("\n".join(header_lines), title="Token Info", expand=False))

    # Warnings
    if warnings:
        w = "\n".join(f"- {w}" for w in warnings)
        console.print(Panel(w, title="Warnings", style="yellow", expand=False))

    # Claims
    if claims:
        t = Table(show_header=True, header_style="bold magenta")
        t.add_column("Claim")
        t.add_column("Value")
        for k, v in claims.items():
            try:
                val = json.dumps(v, indent=2) if isinstance(v, (dict, list)) else str(v)
            except Exception:
                val = repr(v)
            t.add_row(k, val)
        console.print(Panel(t, title="Claims", expand=False))
    else:
        console.print(Panel("No claims parsed.", title="Claims", expand=False))

    # Rating
    color = "green" if rating == "low" else "yellow" if rating == "medium" else "red"
    console.print(Panel(f"[bold]{rating.upper()}[/bold]", title="Security Rating", style=color, expand=False))


def _print_json_result(result: dict):
    """Print JSON-formatted result."""
    def _safe(o):
        try:
            json.dumps(o)
            return o
        except Exception:
            return str(o)

    safe_result = {
        k: (_safe(v) if not isinstance(v, dict) else {kk: _safe(vv) for kk, vv in v.items()})
        for k, v in result.items()
    }
    console.print_json(data=safe_result)


def _exit_by_threshold(result_rating: str, threshold: str):
    """Exit code behavior for CI mode."""
    r_val = RATING_ORDER.get(result_rating, 1)
    t_val = RATING_ORDER.get(threshold, 1)
    if r_val < t_val:
        sys.exit(0)
    if r_val == t_val:
        sys.exit(1)
    sys.exit(2)


# =============================
# CLI definitions
# =============================

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(package_name="jwt-drishti", prog_name="jwt-drishti")
def main():
    """
    [bold cyan]jwt-drishti[/bold cyan]: Lightweight JWT analysis and validation CLI.

    Examples:
    
      Decode a token file: jwt-drishti decode token.txt

      Decode directly from a token string: jwt-drishti decode 'eyJhbGciOi...'

      Verify using a local secret or PEM: jwt-drishti verify token.txt --key key.pem

      Use JSON output for automation: jwt-drishti decode token.txt --json

      Use CI mode (non-zero exit codes on medium/high risk): jwt-drishti decode token.txt --ci --threshold medium
    """
    pass


def _common_options(func):
    """Decorator to add common options (output, CI)"""
    func = click.option("--format", "fmt", type=click.Choice(["text", "json", "sarif"]), default="text",
                       help="Output format.")(func)
    func = click.option("--json", "as_json", is_flag=True,
                       help="Shortcut for --format json.")(func)
    func = click.option("--ci", is_flag=True, help="Enable CI exit codes based on rating.")(func)
    func = click.option("--threshold", type=click.Choice(["low", "medium", "high"]), default="medium",
                       help="CI threshold rating (default: medium).")(func)
    return func


# -----------------------------
# decode command
# -----------------------------
@main.command(help="Decode and analyze a JWT (no signature verification by default).")
@click.argument("token", required=True)
@_common_options
@click.option("--explain", is_flag=True, help="Explain common JWT claims in plain language.")
def decode(token, fmt, as_json, ci, threshold, explain):
    """
    Decode and inspect a JWT.

    TOKEN can be either:
      • A filename (e.g. token.txt)
      • A raw JWT string

    Examples:
      jwt-drishti decode token.txt
      jwt-drishti decode token.txt --format json
      jwt-drishti decode token.txt --ci --threshold high
    """
    try:
        tok = load_token_from_file(token)
    except FileNotFoundError:
        tok = token

    result = analyze_token(tok, verify=False)

    if as_json:
        fmt = "json"

    if fmt == "json":
        _print_json_result(result)
    elif fmt == "sarif":
        console.print("[yellow]SARIF output not yet implemented. Use --format json or text.[/yellow]")
        _print_text_result(result)
    else:
        _print_text_result(result)

    if ci:
        _exit_by_threshold(result.get("rating", "medium"), threshold)


# -----------------------------
# verify command
# -----------------------------
@main.command(help="Verify JWT signature using a key or JWKS endpoint.")
@click.argument("token", required=True)
@click.option("--key", "-k", help="Path to key file (HMAC secret or PEM public key).")
@click.option("--jwks", help="URL to JWKS endpoint (optional).")
@click.option("--kid", help="Key ID to select from JWKS (optional).")
@_common_options
def verify(token, key, jwks, kid, fmt, as_json, ci, threshold):
    """
    Verify a JWT using a shared secret, PEM, or JWKS.

    Examples:
      jwt-drishti verify token.txt --key secret.txt
      jwt-drishti verify token.txt --key public.pem
      jwt-drishti verify token.txt --jwks https://example.com/.well-known/jwks.json
    """
    try:
        tok = load_token_from_file(token)
    except FileNotFoundError:
        tok = token

    verification = {"verified": False, "message": "no verification attempted"}

    if jwks:
        try:
            verified, payload_or_err = verify_with_jwks(tok, jwks, kid)
            verification = {"verified": bool(verified), "message": payload_or_err}
        except Exception as e:
            verification = {"verified": False, "message": f"JWKS verification error: {e}"}
    elif key:
        try:
            keydata = open(key, "r").read()
            verified, payload_or_err = verify_token_with_key(tok, keydata)
            verification = {"verified": bool(verified), "message": payload_or_err}
        except Exception as e:
            console.print(f"[red]Failed to read or verify with key file:[/red] {e}")
            sys.exit(2)
    else:
        console.print("[yellow]No verification key provided.[/yellow]")

    result = analyze_token(tok, verify=True, verification=verification)

    if as_json:
        fmt = "json"

    if fmt == "json":
        _print_json_result(result)
    elif fmt == "sarif":
        console.print("[yellow]SARIF output not yet implemented. Use --format json or text.[/yellow]")
        _print_text_result(result)
    else:
        _print_text_result(result)

    if ci:
        _exit_by_threshold(result.get("rating", "medium"), threshold)


if __name__ == "__main__":
    main()
