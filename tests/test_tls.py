import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

from certsentinel.core import check_target


@contextmanager
def local_tls_server():
    with tempfile.TemporaryDirectory() as directory:
        cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
             "-keyout", str(key), "-out", str(cert)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(4)
        port = listener.getsockname()[1]

        def serve():
            try:
                conn, _ = listener.accept()
                with conn:
                    try:
                        with server_context.wrap_socket(conn, server_side=True):
                            pass
                    except ssl.SSLError:
                        pass
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield port, str(cert)
        finally:
            listener.close()
            thread.join(timeout=5)


class TLSCheckTests(unittest.TestCase):
    def test_uses_verified_tls_and_reports_expiration(self):
        with local_tls_server() as (port, cert):
            context = ssl.create_default_context(cafile=cert)
            result = check_target(f"localhost:{port}", warn_days=1, timeout=2, context=context)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["host"], "localhost")
        self.assertGreater(result["seconds_remaining"], 0)
        self.assertIn("T", result["expires_at"])

    def test_warns_before_threshold(self):
        with local_tls_server() as (port, cert):
            context = ssl.create_default_context(cafile=cert)
            result = check_target(f"localhost:{port}", warn_days=3, timeout=2, context=context)
        self.assertEqual(result["status"], "warning")

    def test_rejects_untrusted_certificate(self):
        with local_tls_server() as (port, _):
            result = check_target(f"localhost:{port}", timeout=2)
        self.assertEqual(result["status"], "error")
        self.assertIn("certificate verify failed", result["error"].lower())

    def test_rejects_wrong_hostname(self):
        with local_tls_server() as (port, cert):
            context = ssl.create_default_context(cafile=cert)
            result = check_target(f"127.0.0.1:{port}", timeout=2, context=context)
        self.assertEqual(result["status"], "error")
        self.assertIn("mismatch", result["error"].lower())


if __name__ == "__main__":
    unittest.main()
