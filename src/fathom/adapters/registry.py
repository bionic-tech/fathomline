"""Adapter selection by operator-confirmed platform class (ADD 04, mirrors backends/registry).

The data-plane :class:`~fathom.backends.registry.BackendRegistry` matches a mountpoint to the
first backend that ``supports()`` it. The control-plane registry is keyed instead on the
**operator-confirmed** :class:`~fathom.adapters.discovery.PlatformClass` (ADD 04: no silent
misclassification — the operator confirms what each device is), with the first registered
adapter for a class winning. ``register`` enforces the structural :class:`PlatformAdapter`
contract exactly as the backend registry does (code-quality #9).

In-process registration only this stage (TrueNAS + Generic). Entry-point/``importlib.metadata``
discovery for third-party adapter packages (ADD 04 extensibility) is deferred until the first
community adapter exists — the Protocol boundary already makes that additive.
"""

from __future__ import annotations

from fathom.adapters.base import PlatformAdapter
from fathom.adapters.discovery import PlatformClass
from fathom.logging import get_logger

_log = get_logger("fathom.adapters.registry")


class NoAdapterError(RuntimeError):
    """Raised when no adapter is registered for a platform class (fail-closed resolution)."""


class AdapterRegistry:
    """An ordered registry of :class:`PlatformAdapter` plugins keyed by platform class."""

    def __init__(self) -> None:
        self._adapters: list[tuple[PlatformClass, PlatformAdapter]] = []

    def register(self, platform: PlatformClass, adapter: PlatformAdapter) -> None:
        """Register ``adapter`` for ``platform`` (registered earlier = higher priority)."""
        if not isinstance(adapter, PlatformAdapter):
            raise TypeError(f"{adapter!r} does not satisfy the PlatformAdapter protocol")
        self._adapters.append((platform, adapter))
        _log.info(
            "adapter registered",
            extra={"platform": platform.value, "adapter": type(adapter).__name__},
        )

    def resolve(self, platform: PlatformClass) -> PlatformAdapter:
        """Return the highest-priority adapter registered for ``platform`` (first match)."""
        for registered, adapter in self._adapters:
            if registered is platform:
                return adapter
        raise NoAdapterError(f"no registered adapter for platform class {platform.value!r}")
