# CertSentinel

A small, dependency-free command-line checker for **the TLS certificate a website actually serves**. It opens a verified HTTPS connection, checks the hostname and trust chain, and reports the certificate's expiry. It is useful for cron jobs, CI checks, and small self-hosted sites where a renewal can fail silently.

> New project: this repository makes no claim of existing users, production adoption, or OpenAI program eligibility.

## Requirements

Python 3.10+; OpenSSL command-line tool is required **only for the local integration tests**. The checker itself uses Python's standard library and system trust store.

## Usage

Run without installing, from the repository directory:

```console
python -m certsentinel --warn-days 30 example.org https://www.python.org/
```

Or install locally and use the console command:

```console
python -m pip install .
certsentinel --json --timeout 5 --warn-days 14 example.org:443 https://www.python.org/
```

Only `https://` URLs and `host[:port]` targets are accepted. For IPv6, use `[::1]:443`. A URL path is ignored: this tests TLS negotiation **before** an HTTP request, not endpoint health. DNS and the machine's CA store must be available.

Example JSON shape (illustrative, not a live result):

```json
[{"target":"example.org","host":"example.org","port":443,"status":"ok","expires_at":"2027-01-01T00:00:00+00:00","seconds_remaining":123456}]
```

Unreachable hosts, invalid chains, and hostname mismatches return `"status":"error"` with an `error` message. Expired certificates also fail TLS verification and appear as errors. The tool **never disables certificate validation**. It does not follow redirects, inspect HTTP responses, test every backend IP, or read local certificate files.

Exit codes: `0` all healthy; `1` one or more within the warning window; `2` any connection/certificate error or invalid CLI arguments. On error, output still includes results for all syntactically valid targets. The warning threshold is inclusive; default 30 days. Each connection timeout defaults to 5 seconds, so a large list can take longer than 5 seconds in total.

Cron example (run daily; direct output to your own log/alerting system):

```cron
0 7 * * * /path/to/python -m certsentinel --json example.org >> /path/to/cert-check.log 2>&1
```

The tool reports results but does **not** send notifications or renew certificates. Integrate the exit code or JSON with your monitoring system; a cron log alone will not alert you.

## Development

```console
python -m unittest discover -s tests -v
```

Tests use a temporary localhost TLS server and self-signed certificate to exercise trust and hostname verification; OpenSSL CLI is needed to generate the test certificate. No credentials or external services are needed for the tests. CI runs the suite on Linux across supported Python versions.

Contributions and bug reports are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under MIT.
