"""Load an :class:`AgentConfig` from a YAML (or JSON) file.

``yaml.safe_load`` parses both YAML and JSON, so one loader covers either format. The
parsed mapping is validated through the same fail-fast :class:`AgentConfig` model used
everywhere else — an invalid config is a startup error, never a silent default (ADD 02).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from fathom.agent.config import AgentConfig


def load_agent_config(path: str | Path) -> AgentConfig:
    """Parse and validate the agent config at ``path``."""
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(f"agent config at {path!s} must be a mapping, got {type(data).__name__}")
    return AgentConfig.model_validate(data)
