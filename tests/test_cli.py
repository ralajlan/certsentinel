import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from certsentinel.cli import main


class CommandLineTests(unittest.TestCase):
    def test_json_returns_warning_exit_status(self):
        results = [
            {"target": "a.example", "host": "a.example", "port": 443, "status": "ok", "expires_at": "2027-01-01T00:00:00+00:00", "seconds_remaining": 100},
            {"target": "b.example", "host": "b.example", "port": 443, "status": "warning", "expires_at": "2026-11-01T00:00:00+00:00", "seconds_remaining": 10},
        ]
        output = io.StringIO()
        with patch("certsentinel.cli.check_target", side_effect=results) as checker, redirect_stdout(output):
            code = main(["--json", "--warn-days", "7", "a.example", "b.example"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue()), results)
        self.assertEqual(checker.call_count, 2)
        self.assertEqual(checker.call_args.kwargs["warn_days"], 7)

    def test_errors_take_precedence_over_warnings(self):
        output = io.StringIO()
        with patch("certsentinel.cli.check_target", return_value={"status": "error", "target": "x", "error": "untrusted"}), redirect_stdout(output):
            code = main(["x"])
        self.assertEqual(code, 2)
        self.assertIn("untrusted", output.getvalue())

    def test_invalid_parameters_rejected(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            main(["--warn-days", "-1", "example.org"])
        self.assertEqual(caught.exception.code, 2)

    def test_module_entrypoint_shows_help(self):
        result = subprocess.run([sys.executable, "-m", "certsentinel", "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--warn-days", result.stdout)


if __name__ == "__main__":
    unittest.main()
