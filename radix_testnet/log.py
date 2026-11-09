"""Structured logging: one JSON object per line, to stderr and to a file.

A harness that only prints to the console is undebuggable once it is packaged and
double-clicked, because there is nothing to look at afterwards. Every event carries
a timestamp, a name and whatever fields matter, and lands in both places.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}


class Log:
    """A minimal JSONL logger. No handlers, no configuration file, no magic."""

    def __init__(self, path: Path | None = None, level: str = "info", stream=None) -> None:
        self.path = Path(path) if path is not None else None
        self.threshold = LEVELS.get(str(level).lower(), 20)
        self.stream = stream if stream is not None else sys.stderr
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, name: str, level: str = "info", **fields) -> dict:
        severity = LEVELS.get(level, 20)
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()), "event": name}
        record.update({key: value for key, value in fields.items()})
        if severity >= self.threshold:
            line = json.dumps(record, default=str, sort_keys=True)
            try:
                print(line, file=self.stream, flush=True)
            except (OSError, ValueError):
                pass
            if self.path is not None:
                try:
                    with self.path.open("a", encoding="utf-8") as handle:
                        handle.write(line + "\n")
                except OSError:
                    pass
        return record
