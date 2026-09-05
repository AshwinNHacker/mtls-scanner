# Usage Guide

## Command-line reference

```
usage: mtls-scanner [-h] [-p PORT] [--targets FILE] [-t TIMEOUT]
                     [-f {text,json,html}] [-o FILE] [--no-color]
                     [--checks CHECK,CHECK,...]
                     [--fail-on {critical,high,medium,low,any,never}] [-q]
                     [--version]
                     [target]

positional arguments:
  target                Target as host, host:port, or [ipv6]:port

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port to scan if not embedded in target (default: 443)
  --targets FILE        File with one host[:port] target per line
  -t TIMEOUT, --timeout TIMEOUT
                        Per-connection timeout in seconds (default: 8)
  -f {text,json,html}, --format {text,json,html}
                        Output format (default: text)
  -o FILE, --output FILE
                        Write report to FILE instead of stdout
  --no-color            Disable ANSI color in text output
  --checks CHECK,CHECK,...
                        Comma-separated list of specific checks to run (default: all)
  --fail-on {critical,high,medium,low,any,never}
                        Exit code 2 if a finding at/above this severity is found (default: any)
  -q, --quiet           Suppress progress output on stderr
  --version             show program's version number and exit
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding met the `--fail-on` threshold |
| `2` | Scan completed; at least one finding met the `--fail-on` threshold |
| `3` | At least one target could not be reached at all |

For multi-target scans (`--targets`), the exit code reflects the worst outcome across all
targets.

## Scanning multiple targets

Create a file with one target per line (`#` starts a comment):

```text
# targets.txt
api.internal.example.com:8443
payments.internal.example.com:8443
10.0.4.12:9443
```

```bash
mtls-scanner --targets targets.txt --format json --output results.json
```

## CI/CD integration

`mtls-scanner` returns a non-zero exit code when misconfigurations are found, so it drops
directly into a pipeline gate:

```yaml
# GitHub Actions example (a job separate from this repo's own CI)
- name: mTLS configuration check
  run: |
    pip install mtls-scanner
    mtls-scanner internal-api.example.com:8443 --fail-on high --format json --output mtls-report.json
- name: Upload report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: mtls-report
    path: mtls-report.json
```

Use `--fail-on critical` to only break the build on the most severe class of finding (accepting
self-signed or wrong-CA certificates), or `--fail-on never` to run the scan purely for
reporting without affecting pipeline status.

## Interpreting a report

- **`VULNERABLE`** — the server accepted a client certificate it should have rejected.
  Treat CRITICAL findings as equivalent to "client authentication is not actually enforced."
- **`SECURE`** — the server correctly rejected the deliberately invalid certificate presented
  for that check. No action needed.
- **`INCONCLUSIVE`** — the scanner couldn't get a clean answer (usually a network condition).
  Re-run; if it persists, see [ARCHITECTURE.md](ARCHITECTURE.md) for what each check does
  under the hood.

See [`CHECKS.md`](CHECKS.md) for what each individual check proves and how to fix it.

## Authorized use

This tool performs live TLS handshakes against its target, including presenting certificates
that a naive intrusion-detection system might flag as anomalous (rapid repeated handshakes
with varying, invalid client certificates from one source). Only run it against:

- Systems you own,
- Systems you have explicit, documented authorization to test (e.g. as part of a penetration
  test or internal security review), or
- Your own local/lab environment (see the bundled [example servers](../examples/README.md)).

Running network scanning or security-testing tools against third-party infrastructure without
authorization may violate the target's acceptable-use policy, terms of service, or applicable
law (e.g. the U.S. Computer Fraud and Abuse Act or equivalent legislation elsewhere),
regardless of intent. When in doubt, don't.
