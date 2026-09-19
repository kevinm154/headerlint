from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from headerlint.cli import main


class CliJsonFormatTests(unittest.TestCase):
    def _write(self, tmpdir: str, name: str, text: str) -> str:
        path = Path(tmpdir) / name
        path.write_text(text)
        return str(path)

    def test_json_output_for_single_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(
                tmpdir, "response.http",
                "HTTP/1.1 200 OK\nContent-Type: text/html\ncontent-type: text/plain\n",
            )
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["--format", "json", path])

        self.assertEqual(code, 1)
        payload = json.loads(out.getvalue())
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["file"], path)
        codes = [f["code"] for f in payload[0]["findings"]]
        self.assertIn("duplicate-header", codes)
        self.assertIn("missing-recommended-header", codes)

    def test_json_output_is_empty_list_for_clean_input(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(
                tmpdir, "clean.http",
                "HTTP/1.1 200 OK\n"
                "Content-Type: text/html\n"
                "Strict-Transport-Security: max-age=31536000\n"
                "X-Content-Type-Options: nosniff\n",
            )
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["--format", "json", path])

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload, [{"file": path, "findings": []}])

    def test_json_output_covers_multiple_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clean = self._write(tmpdir, "clean.http", "Content-Type: text/html\n")
            broken = self._write(tmpdir, "broken.http", "not a header line\n")
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(["--format", "json", "--lenient", clean, broken])

        self.assertEqual(code, 1)
        payload = json.loads(out.getvalue())
        self.assertEqual([entry["file"] for entry in payload], [clean, broken])
        self.assertEqual(payload[0]["findings"], [])
        self.assertEqual(payload[1]["findings"][0]["code"], "malformed-line")

    def test_text_format_is_unchanged_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, "broken.http", "not a header line\n")
            out = io.StringIO()
            with redirect_stdout(out):
                code = main([path])

        self.assertEqual(code, 1)
        self.assertIn("malformed-line", out.getvalue())
        with self.assertRaises(json.JSONDecodeError):
            json.loads(out.getvalue())


if __name__ == "__main__":
    unittest.main()
