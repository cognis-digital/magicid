"""Smoke tests for MAGICID. Standard library only, no network."""
import json
import os
import tempfile
import unittest

from magicid import (
    TOOL_NAME,
    TOOL_VERSION,
    identify_bytes,
    identify_file,
    scan_paths,
)
from magicid.cli import main, render_html, render_json, render_table


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
PE = b"MZ\x90\x00" + b"\x00" * 32
PDF = b"%PDF-1.7\n" + b"trailer\n"
GZIP = b"\x1f\x8b\x08\x00" + b"\x00" * 16
JUNK = b"\x42\x99\x17\x03nothing-here"


class TestIdentifyBytes(unittest.TestCase):
    def test_png_consistent(self):
        ident = identify_bytes(PNG, path="logo.png")
        self.assertEqual(ident.detected_name, "PNG image")
        self.assertEqual(ident.detected_mime, "image/png")
        self.assertFalse(ident.mismatch)
        self.assertEqual(ident.severity, "ok")

    def test_pe_disguised_as_jpg_is_high(self):
        ident = identify_bytes(PE, path="vacation_photo.jpg")
        self.assertEqual(ident.category, "executable")
        self.assertTrue(ident.mismatch)
        self.assertEqual(ident.severity, "high")
        self.assertTrue(any("EXECUTABLE" in f for f in ident.findings))

    def test_pdf_mislabeled_docx_is_medium(self):
        ident = identify_bytes(PDF, path="report.docx")
        self.assertEqual(ident.detected_mime, "application/pdf")
        self.assertTrue(ident.mismatch)
        self.assertEqual(ident.severity, "medium")

    def test_unknown_is_low(self):
        ident = identify_bytes(JUNK, path="mystery.dat")
        self.assertIsNone(ident.detected)
        self.assertEqual(ident.severity, "low")
        self.assertEqual(ident.detected_mime, "application/octet-stream")

    def test_offset_signature_webp(self):
        webp = b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"\x00" * 8
        ident = identify_bytes(webp, path="x.webp")
        self.assertEqual(ident.detected_mime, "image/webp")
        self.assertEqual(ident.severity, "ok")

    def test_no_extension_never_mismatches(self):
        ident = identify_bytes(GZIP, path="archive")
        self.assertFalse(ident.mismatch)
        self.assertEqual(ident.severity, "ok")


class TestFileAndScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._write("a.png", PNG)
        self._write("evil.jpg", PE)
        self._write("doc.docx", PDF)

    def _write(self, name, data):
        with open(os.path.join(self.tmp, name), "wb") as f:
            f.write(data)

    def test_identify_file(self):
        ident = identify_file(os.path.join(self.tmp, "evil.jpg"))
        self.assertEqual(ident.severity, "high")
        self.assertEqual(ident.size, len(PE))

    def test_scan_paths_recursive(self):
        results = scan_paths([self.tmp], recursive=True)
        self.assertEqual(len(results), 3)
        sevs = {os.path.basename(r.path): r.severity for r in results}
        self.assertEqual(sevs["a.png"], "ok")
        self.assertEqual(sevs["evil.jpg"], "high")
        self.assertEqual(sevs["doc.docx"], "medium")


class TestRenderers(unittest.TestCase):
    def setUp(self):
        self.results = [
            identify_bytes(PE, path="evil.jpg"),
            identify_bytes(PNG, path="logo.png"),
            identify_bytes(JUNK, path="x.dat"),
        ]

    def test_table(self):
        out = render_table(self.results)
        self.assertIn(TOOL_NAME, out)
        self.assertIn("HIGH", out)
        self.assertIn("summary:", out)

    def test_json_valid(self):
        out = render_json(self.results)
        data = json.loads(out)
        self.assertEqual(data["tool"], TOOL_NAME)
        self.assertEqual(data["version"], TOOL_VERSION)
        self.assertEqual(data["count"], 3)
        self.assertEqual(data["summary"]["high"], 1)

    def test_html_self_contained(self):
        out = render_html(self.results)
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertIn("<style>", out)
        self.assertIn("evil.jpg", out)
        self.assertNotIn("http://", out)  # no external resources


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        with open(os.path.join(self.tmp, "evil.jpg"), "wb") as f:
            f.write(PE)
        with open(os.path.join(self.tmp, "clean.png"), "wb") as f:
            f.write(PNG)

    def test_version_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_no_command_returns_2(self):
        self.assertEqual(main([]), 2)

    def test_scan_findings_exit_1(self):
        rc = main(["scan", self.tmp, "-r", "--format", "json"])
        self.assertEqual(rc, 1)

    def test_scan_clean_exit_0(self):
        clean = tempfile.mkdtemp()
        with open(os.path.join(clean, "clean.png"), "wb") as f:
            f.write(PNG)
        rc = main(["scan", clean, "-r"])
        self.assertEqual(rc, 0)

    def test_html_out_written(self):
        out = os.path.join(self.tmp, "report.html")
        rc = main(["scan", self.tmp, "-r", "--format", "html", "--out", out])
        self.assertEqual(rc, 1)
        self.assertTrue(os.path.exists(out))
        with open(out, encoding="utf-8") as f:
            self.assertIn("<!DOCTYPE html>", f.read())


class TestHardeningEdgeCases(unittest.TestCase):
    """Tests for error-handling and edge-case paths added during hardening."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    # --- identify_bytes edge cases ----------------------------------------

    def test_empty_bytes_returns_low(self):
        """Empty buffer yields unknown / low severity — no crash."""
        ident = identify_bytes(b"", path="empty.bin")
        self.assertIsNone(ident.detected)
        self.assertEqual(ident.severity, "low")
        self.assertEqual(ident.head_hex, "")

    def test_identify_bytes_no_path(self):
        """identify_bytes with path=None must not raise and must not mismatch."""
        ident = identify_bytes(PNG, path=None)
        self.assertEqual(ident.detected_name, "PNG image")
        self.assertFalse(ident.mismatch)  # no declared extension → no mismatch

    # --- identify_file error paths ----------------------------------------

    def test_identify_file_missing_path_raises_oserror(self):
        """Non-existent path raises OSError (FileNotFoundError)."""
        with self.assertRaises(OSError):
            identify_file(os.path.join(self.tmp, "does_not_exist.png"))

    def test_identify_file_directory_raises(self):
        """Passing a directory to identify_file raises IsADirectoryError."""
        with self.assertRaises((IsADirectoryError, OSError)):
            identify_file(self.tmp)

    # --- scan_paths error paths -------------------------------------------

    def test_scan_nonexistent_path_returns_finding(self):
        """scan_paths never raises; a missing path becomes a finding entry."""
        ghost = os.path.join(self.tmp, "ghost.exe")
        results = scan_paths([ghost])
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].findings)
        self.assertEqual(results[0].severity, "low")

    def test_scan_empty_paths_list(self):
        """Calling scan_paths with an empty list returns an empty result."""
        results = scan_paths([])
        self.assertEqual(results, [])

    def test_scan_empty_file_returns_low(self):
        """A zero-byte file produces an unknown / low-severity result."""
        path = self._write("empty.dat", b"")
        results = scan_paths([path])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].severity, "low")
        self.assertIsNone(results[0].detected)

    # --- CLI error paths --------------------------------------------------

    def test_cli_scan_nonexistent_path_exits_1(self):
        """scan with a path that does not exist returns exit-code 1 (findings present)."""
        ghost = os.path.join(self.tmp, "ghost.bin")
        rc = main(["scan", ghost])
        self.assertEqual(rc, 1)

    def test_cli_bad_out_dir_returns_2(self):
        """--out with a missing parent directory returns exit-code 2."""
        src = self._write("ok.png", PNG)
        bad_out = os.path.join(self.tmp, "missing_subdir", "report.html")
        rc = main(["scan", src, "--out", bad_out])
        self.assertEqual(rc, 2)

    # --- mcp_server helper -----------------------------------------------

    def test_mcp_scan_to_json_empty_target(self):
        """_scan_to_json with an empty string returns an error JSON, not a crash."""
        from magicid.mcp_server import _scan_to_json
        result = json.loads(_scan_to_json(""))
        self.assertIn("error", result)

    def test_mcp_scan_to_json_nonexistent(self):
        """_scan_to_json with a non-existent path returns an error JSON."""
        from magicid.mcp_server import _scan_to_json
        result = json.loads(_scan_to_json("/no/such/path/file.bin"))
        self.assertIn("error", result)

    def test_mcp_scan_to_json_valid_file(self):
        """_scan_to_json with a real file returns a JSON findings payload."""
        from magicid.mcp_server import _scan_to_json
        path = self._write("test.png", PNG)
        result = json.loads(_scan_to_json(path))
        self.assertIn("count", result)
        self.assertIn("results", result)
        self.assertEqual(result["count"], 1)


class TestWebhook(unittest.TestCase):
    """Tests for integrations/webhook.py input validation (no network calls)."""

    def _run(self, argv, stdin=""):
        """Call webhook main() with controlled argv and stdin."""
        import io
        import sys
        from integrations.webhook import main as webhook_main

        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin)
        try:
            return webhook_main(argv)
        finally:
            sys.stdin = old_stdin

    def test_missing_scheme_returns_2(self):
        """A URL without http/https scheme must be rejected with exit code 2."""
        rc = self._run(["--url", "ftp://example.com/hook"])
        self.assertEqual(rc, 2)

    def test_empty_url_returns_2(self):
        """An empty URL must be rejected with exit code 2."""
        rc = self._run(["--url", "   "])
        self.assertEqual(rc, 2)

    def test_empty_stdin_returns_2(self):
        """Empty stdin (nothing to post) must return exit code 2, not crash."""
        rc = self._run(["--url", "https://example.com/hook"], stdin="   ")
        self.assertEqual(rc, 2)

    def test_invalid_json_stdin_returns_2(self):
        """Non-JSON stdin must be rejected with exit code 2 before any network call."""
        rc = self._run(["--url", "https://example.com/hook"], stdin="{not valid json}")
        self.assertEqual(rc, 2)

    def test_malformed_header_returns_2(self):
        """A --header value with no key must return exit code 2."""
        rc = self._run(
            ["--url", "https://example.com/hook", "--header", ":bad"],
            stdin='{"ok": true}',
        )
        self.assertEqual(rc, 2)

    def test_url_missing_host_returns_2(self):
        """A URL with scheme but no host must be rejected."""
        rc = self._run(["--url", "https:///path"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
