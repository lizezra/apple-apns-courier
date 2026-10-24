"""Restrictive local storage for APNs token files."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def write_secret(path: str | Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def read_secret(path: str | Path) -> bytes:
    data = Path(path).read_bytes()
    if not data:
        raise ValueError(f"secret token file is empty: {path}")
    return data


def save_token_state(
    directory: str | Path,
    topic: str,
    base_token: bytes,
    scoped_token: bytes,
) -> dict:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    write_secret(directory / "base-token.bin", base_token)
    write_secret(directory / "scoped-token.bin", scoped_token)
    metadata = {
        "topic": topic,
        "base_token_bytes": len(base_token),
        "base_token_sha256": hashlib.sha256(base_token).hexdigest(),
        "scoped_token_bytes": len(scoped_token),
        "scoped_token_sha256": hashlib.sha256(scoped_token).hexdigest(),
        "warning": "Token files are secrets. Do not commit or publish them.",
    }
    (directory / "metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n",
        encoding="utf-8",
    )
    return metadata
