"""Command-line interface for mtls-scanner."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from mtls_scanner import __version__
from mtls_scanner.report import RENDERERS
from mtls_scanner.scanner import MTLSScanner


def _parse_target(raw: str, default_port: int) -> tuple:
    raw = raw.strip()
    if raw.startswith("["):  # bracketed IPv6, e.g. [::1]:8443 or [::1]
        closing = raw.find("]")
        host = raw[1:closing]
        rest = raw[closing + 1:]  # "" or ":8443"
        port = int(rest[1:]) if rest.startswith(":") and rest[1:] else default_port
        return host, port
    if raw.count(":") == 1:
        host, port_str = raw.split(":")
        return host, int(port_str)
    return raw, default_port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mtls-scanner",
        description=(
            "Scans mTLS-enabled endpoints for client-certificate-chain "
            "validation misconfigurations (accepting self-signed, expired, "
            "untrusted-CA, or otherwise invalid client certificates)."
        ),
        epilog=(
            "Example:\n"
            "  mtls-scanner api.internal.example.com:8443\n"
            "  mtls-scanner --format json --output report.json 10.0.0.5 -p 8443\n"
            "  mtls-scanner --targets targets.txt --format html --output report.html\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target", nargs="?", help="Target as host, host:port, or [ipv6]:port"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=443, help="Port to scan if not embedded in target (default: 443)"
    )
    parser.add_argument(
        "--targets", metavar="FILE", help="File with one host[:port] target per line"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=8.0, help="Per-connection timeout in seconds (default: 8)"
    )
    parser.add_argument(
        "-f", "--format", choices=list(RENDERERS.keys()), default="text", help="Output format (default: text)"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE", help="Write report to FILE instead of stdout"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI color in text output"
    )
    parser.add_argument(
        "--checks", metavar="CHECK,CHECK,...",
        help="Comma-separated list of specific checks to run (default: all)",
    )
    parser.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low", "any", "never"],
        default="any",
        help="Exit code 2 if a finding at/above this severity is found (default: any)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress progress output on stderr"
    )
    parser.add_argument(
        "--version", action="version", version=f"mtls-scanner {__version__}"
    )
    return parser


def _severity_threshold_met(report, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    if not report.is_vulnerable:
        return False
    if fail_on == "any":
        return True
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return report.highest_severity.rank >= order[fail_on]


def _read_targets_file(path: str, default_port: int) -> List[tuple]:
    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(_parse_target(line, default_port))
    return targets


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.target and not args.targets:
        parser.error("Provide a target, or use --targets FILE")

    targets = []
    if args.target:
        targets.append(_parse_target(args.target, args.port))
    if args.targets:
        targets.extend(_read_targets_file(args.targets, args.port))

    checks = args.checks.split(",") if args.checks else None

    reports = []
    for host, port in targets:
        if not args.quiet:
            print(f"[*] Scanning {host}:{port} ...", file=sys.stderr)

        def progress(check_id: str, status: str, _host=host):
            if not args.quiet:
                print(f"    [{_host}] {check_id}: {status}", file=sys.stderr)

        scanner = MTLSScanner(
            host, port, timeout=args.timeout, checks=checks,
            progress_callback=None if args.quiet else progress,
        )
        report = scanner.run()
        reports.append(report)

    renderer = RENDERERS[args.format]
    if args.format == "text":
        output = "\n\n".join(renderer(r, use_color=not args.no_color) for r in reports)
    elif len(reports) == 1:
        output = renderer(reports[0])
    else:
        import json
        output = json.dumps([r.to_dict() for r in reports], indent=2, default=str) if args.format == "json" \
            else "\n<hr/>\n".join(renderer(r) for r in reports)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        if not args.quiet:
            print(f"[*] Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    exit_code = 0
    for report in reports:
        if report.errors:
            exit_code = max(exit_code, 3)
        elif _severity_threshold_met(report, args.fail_on):
            exit_code = max(exit_code, 2)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
