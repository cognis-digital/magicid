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


if __name__ == "__main__":
    unittest.main()
