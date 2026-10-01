"""Exclusive file creation and bounded untrusted input."""

import json
import os
from pathlib import Path


def write_new(path, data, mode=0o600):
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data.encode("utf-8") if isinstance(data, str) else data)
    return path


def read_json(path, limit=20_000_000):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Input exceeds size limit")
    return json.loads(raw)
