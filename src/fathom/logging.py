"""Structured JSON logging (Framework Principle #6).

Every record carries the mandatory fields — ``severity``, ``message``, ``component``,
``trace_id``, ``timestamp`` — and nothing is ever emitted via ``print`` on a production
path (standards/18 §7). Use :func:`get_logger` to obtain a component-scoped logger and
:func:`configure_logging` once at process start.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JsonFormatter(logging.Formatter):
    """Render a :class:`logging.LogRecord` as a single-line JSON object.

    The mandatory fields are always present. Anything passed through ``extra`` is
    merged in, so structured context (``trace_id``, ``host_id``, counts, …) travels
    with the record rather than being interpolated into the message string.
    """

    _RESERVED = frozenset(logging.makeLogRecord({}).__dict__)

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "severity": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
            "trace_id": getattr(record, "trace_id", None),
        }
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(level: int = logging.INFO) -> None:
    """Install the JSON formatter on the root logger (idempotent)."""
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


def get_logger(component: str) -> logging.Logger:
    """Return a logger namespaced to ``component`` (e.g. ``"fathom.agent.walker"``)."""
    return logging.getLogger(component)
