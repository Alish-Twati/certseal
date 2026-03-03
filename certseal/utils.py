"""
Utility module for CertSeal.

Provides base64 helpers, file I/O, JSON utilities, and banner printing.
"""

import base64
import json


def bytes_to_base64(data: bytes) -> str:
    """Encode bytes to a base64 string.

    Args:
        data: Bytes to encode.

    Returns:
        Base64-encoded string.
    """
    return base64.b64encode(data).decode("utf-8")


def base64_to_bytes(data: str) -> bytes:
    """Decode a base64 string to bytes.

    Args:
        data: Base64-encoded string.

    Returns:
        Decoded bytes.
    """
    return base64.b64decode(data)


def save_to_file(data: bytes, filepath: str) -> None:
    """Write bytes to a file.

    Args:
        data: Bytes to write.
        filepath: Destination file path.
    """
    with open(filepath, "wb") as f:
        f.write(data)


def load_from_file(filepath: str) -> bytes:
    """Read bytes from a file.

    Args:
        filepath: Source file path.

    Returns:
        File contents as bytes.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    with open(filepath, "rb") as f:
        return f.read()


def save_json(data: dict, filepath: str) -> None:
    """Serialise a dictionary to a JSON file.

    Args:
        data: Dictionary to serialise.
        filepath: Destination file path.
    """
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_json(filepath: str) -> dict:
    """Load a dictionary from a JSON file.

    Args:
        filepath: Source file path.

    Returns:
        Parsed dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def print_banner() -> None:
    """Print the CertSeal ASCII art banner to stdout."""
    banner = r"""
  ____          _   ____            _
 / ___|___ _ __| |_/ ___|  ___  __ _| |
| |   / _ \ '__| __\___ \ / _ \/ _` | |
| |__|  __/ |  | |_ ___) |  __/ (_| | |
 \____\___|_|   \__|____/ \___|\__,_|_|

 CertSeal v1.0.0 — Open-source PKI Cryptographic Tool
 Inspired by CrypTool (https://www.cryptool.org)
"""
    print(banner)
