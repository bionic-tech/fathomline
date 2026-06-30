"""``settings_override`` + ``settings_version`` ORM tables (ADR-038) — the runtime settings store.

Fathom's configuration is env-seeded (``FATHOM_*`` → :class:`~fathom.core.settings.Settings`), but
the operator can override a setting **in-app, without a restart**: an override row here wins over
the env default (in-app-value-wins; the env only seeds the default). Non-secret values are stored as
JSON; **secret** values (API keys, channel webhooks/passwords) are stored Fernet-encrypted at rest
and are admin-revealable. ``settings_version`` is a single-row monotonic counter bumped on every
mutation so workers/other processes can cheaply detect a change and reload (live reload). Reuses the
catalogue ``Base`` so one metadata / one Alembic chain governs the schema; types are portable
(PostgreSQL + SQLite).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from fathom.core.catalogue.models import Base

# The fixed primary key of the single ``settings_version`` row (a process never inserts a second).
SETTINGS_VERSION_ID = 1


class SettingsOverride(Base):
    """One in-app override of a :class:`Settings` field (in-app value wins over the env default)."""

    __tablename__ = "settings_override"

    # The Settings field name (e.g. "concierge_enabled"); the override key IS the setting key.
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    # The stored value: a JSON-encoded scalar/list for a non-secret setting, or urlsafe-base64
    # Fernet ciphertext when ``is_secret`` is True. Never the raw secret in plaintext.
    value: Mapped[str] = mapped_column(Text)
    # True when ``value`` is Fernet ciphertext (a secret); the read surface masks it and only the
    # admin-only, step-up-gated reveal endpoint decrypts it.
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # The principal subject who last set this override (audit trail; null for system/seed writes).
    updated_by: Mapped[str | None] = mapped_column(String(255), default=None)


class SettingsVersion(Base):
    """Single-row monotonic version counter — bumped on every override mutation for live reload."""

    __tablename__ = "settings_version"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    version: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
