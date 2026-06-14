"""Core engine: magic-byte identification of true file types.

Pure standard library. No network, no third-party deps.

The engine reads the leading bytes of a file (and a couple of interior
offsets where the format requires it), matches them against a curated
signature table, and reports the *true* type. It then compares that
truth against the filename extension and flags mismatches — the classic
\"a .jpg that is really a Windows .exe\" trick used to smuggle payloads.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable, Optional


# How many bytes we sniff from the head of each file.
SNIFF_LEN = 4096


@dataclass(frozen=True)
class Signature:
    """A magic-byte signature.

    pattern   : bytes that must appear at `offset`.
    offset    : byte offset where pattern must match.
    name      : human label for the format.
    mime      : canonical MIME type.
    extensions: extensions normally associated with this type.
    category  : coarse grouping (image, archive, executable, ...).
    description: short note about the format.
    """

    name: str
    mime: str
    pattern: bytes
    offset: int = 0
    extensions: tuple[str, ...] = ()
    category: str = "data"
    description: str = ""

    def matches(self, head: bytes) -> bool:
        end = self.offset + len(self.pattern)
        if len(head) < end:
            return False
        return head[self.offset:end] == self.pattern


# Executable / OS-loadable formats are the highest-risk class when they
# masquerade behind a benign extension, so we tag them explicitly.
EXECUTABLE_CATEGORIES = {"executable", "script"}

# Curated, ordered signature table. Longer / more-specific patterns are
# placed before shorter generic ones so the first match wins.
SIGNATURES: tuple[Signature, ...] = (
    # --- Executables ---------------------------------------------------
    Signature("Windows PE executable", "application/vnd.microsoft.portable-executable",
              b"MZ", 0, (".exe", ".dll", ".sys"), "executable",
              "DOS/Windows PE — runnable code"),
    Signature("ELF executable", "application/x-elf",
              b"\x7fELF", 0, (".elf", ".so", ".o", ""), "executable",
              "Unix/Linux ELF — runnable code"),
    Signature("Mach-O 64-bit executable", "application/x-mach-binary",
              b"\xcf\xfa\xed\xfe", 0, (".dylib", ".bundle", ""), "executable",
              "macOS Mach-O 64-bit — runnable code"),
    Signature("Mach-O 32-bit executable", "application/x-mach-binary",
              b"\xce\xfa\xed\xfe", 0, ("",), "executable",
              "macOS Mach-O 32-bit — runnable code"),
    Signature("Java class file", "application/x-java-applet",
              b"\xca\xfe\xba\xbe", 0, (".class",), "executable",
              "JVM bytecode"),
    Signature("Shell script", "text/x-shellscript",
              b"#!", 0, (".sh", ".bash", ""), "script",
              "Shebang script — interpreter-run code"),
    # --- Archives / compressed ----------------------------------------
    Signature("ZIP archive", "application/zip",
              b"PK\x03\x04", 0, (".zip", ".jar", ".apk", ".docx", ".xlsx",
                                 ".pptx", ".odt", ".epub"), "archive",
              "ZIP container (also OOXML/JAR/APK)"),
    Signature("ZIP archive (empty)", "application/zip",
              b"PK\x05\x06", 0, (".zip",), "archive",
              "Empty ZIP container"),
    Signature("RAR archive", "application/vnd.rar",
              b"Rar!\x1a\x07", 0, (".rar",), "archive",
              "RAR archive"),
    Signature("7-Zip archive", "application/x-7z-compressed",
              b"7z\xbc\xaf\x27\x1c", 0, (".7z",), "archive",
              "7-Zip archive"),
    Signature("gzip compressed", "application/gzip",
              b"\x1f\x8b", 0, (".gz", ".tgz"), "archive",
              "gzip stream"),
    Signature("bzip2 compressed", "application/x-bzip2",
              b"BZh", 0, (".bz2",), "archive",
              "bzip2 stream"),
    Signature("XZ compressed", "application/x-xz",
              b"\xfd7zXZ\x00", 0, (".xz",), "archive",
              "XZ stream"),
    Signature("Zstandard compressed", "application/zstd",
              b"\x28\xb5\x2f\xfd", 0, (".zst",), "archive",
              "Zstandard stream"),
    # --- Documents -----------------------------------------------------
    Signature("PDF document", "application/pdf",
              b"%PDF-", 0, (".pdf",), "document",
              "Portable Document Format"),
    Signature("RTF document", "application/rtf",
              b"{\\rtf", 0, (".rtf",), "document",
              "Rich Text Format"),
    Signature("OLE compound document", "application/x-ole-storage",
              b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0,
              (".doc", ".xls", ".ppt", ".msi"), "document",
              "Legacy MS Office / MSI compound binary"),
    # --- Images --------------------------------------------------------
    Signature("PNG image", "image/png",
              b"\x89PNG\r\n\x1a\n", 0, (".png",), "image",
              "PNG raster image"),
    Signature("JPEG image", "image/jpeg",
              b"\xff\xd8\xff", 0, (".jpg", ".jpeg"), "image",
              "JPEG raster image"),
    Signature("GIF image", "image/gif",
              b"GIF8", 0, (".gif",), "image",
              "GIF raster image"),
    Signature("BMP image", "image/bmp",
              b"BM", 0, (".bmp",), "image",
              "Windows bitmap"),
    Signature("WebP image", "image/webp",
              b"WEBP", 8, (".webp",), "image",
              "WebP image (RIFF container)"),
    Signature("TIFF image (LE)", "image/tiff",
              b"II*\x00", 0, (".tif", ".tiff"), "image",
              "TIFF little-endian"),
    Signature("TIFF image (BE)", "image/tiff",
              b"MM\x00*", 0, (".tif", ".tiff"), "image",
              "TIFF big-endian"),
    Signature("Windows icon", "image/x-icon",
              b"\x00\x00\x01\x00", 0, (".ico",), "image",
              "ICO icon"),
    # --- Audio / video -------------------------------------------------
    Signature("ID3 / MP3 audio", "audio/mpeg",
              b"ID3", 0, (".mp3",), "audio",
              "MP3 with ID3 tag"),
    Signature("WAV audio", "audio/wav",
              b"WAVE", 8, (".wav",), "audio",
              "WAV audio (RIFF container)"),
    Signature("OGG media", "application/ogg",
              b"OggS", 0, (".ogg", ".oga", ".ogv"), "audio",
              "Ogg container"),
    Signature("FLAC audio", "audio/flac",
              b"fLaC", 0, (".flac",), "audio",
              "FLAC audio"),
    Signature("MP4 / ISO media", "video/mp4",
              b"ftyp", 4, (".mp4", ".m4a", ".mov"), "video",
              "ISO base media (MP4/MOV/M4A)"),
    # --- Misc structured ----------------------------------------------
    Signature("SQLite database", "application/vnd.sqlite3",
              b"SQLite format 3\x00", 0, (".sqlite", ".db", ".sqlite3"),
              "database", "SQLite 3 database"),
    Signature("XML document", "application/xml",
              b"<?xml", 0, (".xml", ".svg", ".xhtml"), "text",
              "XML document"),
)


@dataclass
class Identification:
    """Result of identifying a single file (or buffer)."""

    path: Optional[str]
    size: Optional[int]
    declared_ext: str
    detected: Optional[Signature]
    head_hex: str
    findings: list[str] = field(default_factory=list)

    @property
    def detected_name(self) -> str:
        return self.detected.name if self.detected else "unknown"

    @property
    def detected_mime(self) -> str:
        return self.detected.mime if self.detected else "application/octet-stream"

    @property
    def category(self) -> str:
        return self.detected.category if self.detected else "unknown"

    @property
    def severity(self) -> str:
        """high  -> extension hides an executable / strong mismatch
        medium -> extension/type disagree (possible mislabel)
        low    -> unknown type
        ok     -> consistent / harmless
        """
        if self.detected is None:
            return "low"
        ext_ok = (not self.declared_ext) or (self.declared_ext in self.detected.extensions)
        if not ext_ok and self.category in EXECUTABLE_CATEGORIES:
            return "high"
        if not ext_ok:
            return "medium"
        return "ok"

    @property
    def mismatch(self) -> bool:
        if self.detected is None:
            return False
        if not self.declared_ext:
            return False
        return self.declared_ext not in self.detected.extensions

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "declared_ext": self.declared_ext,
            "detected_name": self.detected_name,
            "detected_mime": self.detected_mime,
            "category": self.category,
            "extension_mismatch": self.mismatch,
            "severity": self.severity,
            "head_hex": self.head_hex,
            "findings": self.findings,
        }


def _normalize_ext(path: Optional[str]) -> str:
    if not path:
        return ""
    _, ext = os.path.splitext(path)
    return ext.lower()


def identify_bytes(head: bytes, path: Optional[str] = None,
                   size: Optional[int] = None) -> Identification:
    """Identify a buffer of head bytes. The first matching signature wins."""
    detected: Optional[Signature] = None
    for sig in SIGNATURES:
        if sig.matches(head):
            detected = sig
            break

    declared = _normalize_ext(path)
    head_hex = head[:16].hex(" ")
    ident = Identification(
        path=path,
        size=size,
        declared_ext=declared,
        detected=detected,
        head_hex=head_hex,
    )

    if detected is None:
        ident.findings.append("Unknown magic bytes — type could not be identified.")
    elif ident.mismatch:
        msg = (f"Extension '{declared}' does not match true type "
               f"'{detected.name}' ({detected.mime}).")
        if detected.category in EXECUTABLE_CATEGORIES:
            msg += " EXECUTABLE content hidden behind a non-executable extension."
        ident.findings.append(msg)
    return ident


def identify_file(path: str) -> Identification:
    """Identify a file on disk by reading its head bytes.

    Raises ``OSError`` for unreadable files so that callers can decide
    whether to skip or propagate.  Directories are never valid targets and
    raise ``IsADirectoryError``.
    """
    if not isinstance(path, str) or not path:
        raise ValueError(f"path must be a non-empty string, got {path!r}")
    # os.path.getsize follows symlinks; if the target is a directory we get a
    # misleading size, so guard explicitly before opening.
    if os.path.isdir(path):
        raise IsADirectoryError(f"is a directory, not a file: {path}")
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(SNIFF_LEN)
    return identify_bytes(head, path=path, size=size)


def _iter_files(paths: Iterable[str], recursive: bool) -> Iterable[tuple[str, str | None]]:
    """Yield ``(file_path, error_or_None)`` pairs.

    Directories are expanded; regular files are yielded as-is.
    Paths that do not exist or are not accessible yield the path with an
    error message so callers can report them cleanly rather than receiving
    a raw OS exception later.
    """
    for p in paths:
        if not isinstance(p, str) or not p:
            yield ("", "path must be a non-empty string")
            continue
        if os.path.isdir(p):
            if recursive:
                for root, _dirs, files in os.walk(p):
                    for name in sorted(files):
                        yield (os.path.join(root, name), None)
            else:
                try:
                    names = sorted(os.listdir(p))
                except OSError as exc:
                    yield (p, f"Cannot list directory: {exc}")
                    continue
                for name in names:
                    full = os.path.join(p, name)
                    if os.path.isfile(full):
                        yield (full, None)
        elif os.path.exists(p):
            yield (p, None)
        else:
            yield (p, f"Path does not exist: {p}")


def scan_paths(paths: Iterable[str], recursive: bool = False) -> list[Identification]:
    """Identify every file under the given paths.

    Never raises — all errors (missing paths, permission denied, unexpected
    OS-level failures) are captured as ``Identification`` entries with a
    finding that describes the problem.
    """
    results: list[Identification] = []
    for path, pre_error in _iter_files(paths, recursive):
        if pre_error is not None:
            ident = Identification(
                path=path or None,
                size=None,
                declared_ext=_normalize_ext(path) if path else "",
                detected=None,
                head_hex="",
            )
            ident.findings.append(pre_error)
            results.append(ident)
            continue
        try:
            results.append(identify_file(path))
        except (OSError, ValueError) as exc:
            ident = Identification(
                path=path, size=None, declared_ext=_normalize_ext(path),
                detected=None, head_hex="",
            )
            ident.findings.append(f"Could not read file: {exc}")
            results.append(ident)
        except Exception as exc:  # noqa: BLE001
            # Unexpected error (e.g. MemoryError on a huge file); report and continue.
            ident = Identification(
                path=path, size=None, declared_ext=_normalize_ext(path),
                detected=None, head_hex="",
            )
            ident.findings.append(f"Unexpected error reading file: {type(exc).__name__}: {exc}")
            results.append(ident)
    return results
