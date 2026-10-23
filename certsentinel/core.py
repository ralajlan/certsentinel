"""TLS certificate checks with verified hostnames and trust chains."""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit


def parse_target(target: str) -> tuple[str, int]:
    """Return (hostname, port) for an HTTPS URL or host[:port]."""
    target = target.strip()
    if not target:
        raise ValueError("target is empty")
    if "://" not in target and "/" in target:
        raise ValueError("bare host targets cannot contain paths")
    try:
        url = urlsplit(target if "://" in target else "https://" + target)
        if url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None:
            raise ValueError("expected an HTTPS host without credentials")
        port = 443 if url.port is None else url.port
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        return url.hostname, port
    except ValueError as exc:
        raise ValueError(f"invalid target {target!r}: {exc}") from exc


def check_target(
    target: str, *, warn_days: int = 30, timeout: float = 5.0,
    context: ssl.SSLContext | None = None,
) -> dict:
    """Check the presented HTTPS certificate using normal TLS verification.

    Return a structured result, including errors for unreachable or untrusted hosts.
    """
    host, port = parse_target(target)
    if warn_days < 0 or timeout <= 0:
        raise ValueError("warn_days must be nonnegative and timeout must be positive")
    result = {"target": target, "host": host, "port": port}
    try:
        tls_context = context if context is not None else ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as connection:
            with tls_context.wrap_socket(connection, server_hostname=host) as tls:
                certificate = tls.getpeercert()
        expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), timezone.utc)
        remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
        result.update({
            "status": "warning" if remaining <= warn_days * 86400 else "ok",
            "expires_at": expiry.isoformat(),
            "seconds_remaining": int(remaining),
        })
    except (OSError, ValueError, KeyError) as exc:
        result.update({"status": "error", "error": str(exc)})
    return result
