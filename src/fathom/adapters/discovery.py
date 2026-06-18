"""Onboarding discovery: probe, *suggest*, then operator-confirm a platform class (ADD 04).

When a host is added, the system does **not** assume how to talk to it (ADD 04 "Device
discovery"). It may *suggest* a class from probe signals (an ``/etc/version`` TrueNAS marker,
a DSM endpoint, …), but the operator confirms — no silent misclassification (ADD 04 Review
Readiness, AR-029). :func:`suggest_platform` is therefore a **non-authoritative hint only**;
the authoritative platform class is whatever the operator records in :class:`AdapterSpec`.

This module ships the config/probe layer only. The onboarding UI and its persistence are a
separate subsystem; here we model the shape they will populate.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class PlatformClass(StrEnum):
    """The supported control-plane platform classes (ADD 04 discovery flow).

    Core ships adapters for :attr:`TRUENAS` and :attr:`GENERIC_LINUX`; the NAS classes are
    sketched so the Protocol is proven against more than one vendor and built on demand.
    """

    TRUENAS = "truenas"
    SYNOLOGY = "synology"
    QNAP = "qnap"
    UNRAID = "unraid"
    GENERIC_LINUX = "generic-linux"
    GENERIC_WINDOWS = "generic-windows"


class ProbeSignals(BaseModel):
    """Read-only signals an onboarding probe gathered about a host (all optional, best-effort).

    These are *hints*, not facts: a NAS may hide its banner, a generic host may coincidentally
    expose a matching path. The operator always confirms the final class.
    """

    model_config = ConfigDict(extra="forbid")

    # Contents of a version/identity file if one was readable (e.g. TrueNAS ``/etc/version``).
    version_banner: str | None = None
    # Whether the host responded on a vendor control-plane port/endpoint during the probe.
    api_endpoint_reachable: bool = False
    # OS family as reported by the probe (``linux`` | ``windows`` | ``unknown``).
    os_family: str | None = None


def suggest_platform(signals: ProbeSignals) -> PlatformClass | None:
    """Suggest a platform class from probe ``signals`` — a hint only, never authoritative.

    Returns ``None`` when nothing distinctive matched, so the caller prompts the operator
    rather than guessing. Matching is deliberately conservative: a wrong *suggestion* the
    operator can override is fine; a wrong *silent* classification is not (ADD 04, AR-029).
    """
    banner = (signals.version_banner or "").lower()
    if "truenas" in banner:
        return PlatformClass.TRUENAS
    if "synology" in banner or "dsm" in banner:
        return PlatformClass.SYNOLOGY
    if "qnap" in banner or "qts" in banner:
        return PlatformClass.QNAP
    if "unraid" in banner:
        return PlatformClass.UNRAID
    os_family = (signals.os_family or "").lower()
    if os_family == "windows":
        return PlatformClass.GENERIC_WINDOWS
    if os_family == "linux":
        return PlatformClass.GENERIC_LINUX
    return None


class AdapterSpec(BaseModel):
    """The operator-confirmed adapter assignment for one host (the authoritative record).

    ``platform`` is what the operator confirmed (possibly overriding :func:`suggest_platform`).
    ``suggested`` retains the probe's non-authoritative hint for audit/UI ("we guessed X, you
    confirmed Y"). The connection details live in :class:`~fathom.adapters.config.AdapterConfig`
    and are referenced by ``host_id``; this model is the discovery-layer envelope.
    """

    model_config = ConfigDict(extra="forbid")

    host_id: str = Field(min_length=1)
    platform: PlatformClass
    suggested: PlatformClass | None = None
    confirmed: bool = False
