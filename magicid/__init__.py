"""MAGICID — identify true file types by magic bytes (beats extensions).

Spirit of file/libmagic: know your bytes.
"""
from .core import (
    Signature,
    Identification,
    SIGNATURES,
    identify_bytes,
    identify_file,
    scan_paths,
)

TOOL_NAME = "magicid"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Signature",
    "Identification",
    "SIGNATURES",
    "identify_bytes",
    "identify_file",
    "scan_paths",
]
