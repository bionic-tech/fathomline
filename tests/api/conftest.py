"""Fixtures for API/catalogue tests — a real ASGI app over a temp SQLite catalogue."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager

from fathom.api.app import create_app
from fathom.auth.models import RoleAssignment, User
from fathom.auth.passwords import hash_password
from fathom.auth.principal import Role
from fathom.auth.sessions import create_session
from fathom.core import db
from fathom.core.settings import Settings


@pytest.fixture
async def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'catalogue.db'}",
        auto_create_schema=True,
        # The test transport speaks http:// — emit a non-Secure cookie so httpx stores it.
        session_cookie_secure=False,
    )


@pytest.fixture
async def api_client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    await db.dispose_engine()
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


def batch(*, mountpoint: str = "/mnt/pool", entries: list[dict] | None = None, **over) -> dict:
    """Build a valid ingest batch body."""
    body = {
        "host": {"name": "nas-1", "os": "TrueNAS", "agent_version": "0.1.0"},
        "volume": {
            "mountpoint": mountpoint,
            "fs_type": "zfs",
            "device": "tank",
            "transport": "sata",
            "total": 1000,
            "used": 400,
            "free": 600,
        },
        "mode": "metadata",
        "entries": entries
        if entries is not None
        else [
            _entry(mountpoint, "", 1, is_dir=True),
            _entry(mountpoint, "movies", 2, is_dir=True),
            _entry(mountpoint, "movies/a.mkv", 3, size=100),
            _entry(mountpoint, "movies/b.mkv", 4, size=200),
            _entry(mountpoint, "docs", 5, is_dir=True),
            _entry(mountpoint, "docs/notes.txt", 6, size=50),
        ],
    }
    body.update(over)
    return body


def _entry(mount: str, rel: str, inode: int, *, size: int = 0, is_dir: bool = False) -> dict:
    path = mount if rel == "" else f"{mount}/{rel}"
    name = mount.rsplit("/", 1)[-1] if rel == "" else rel.rsplit("/", 1)[-1]
    return {
        "path": path,
        "name": name,
        "is_dir": is_dir,
        "is_symlink": False,
        "size_logical": size,
        "size_on_disk": size,
        "mtime": 1000.0,
        "ctime": 1000.0,
        "uid": 568,
        "gid": 568,
        "inode": inode,
        "flags": {},
    }


FINGERPRINT_HEADER = {"X-Client-Cert-Fingerprint": "ab:cd:ef:01"}


async def seed_principal(
    *,
    username: str = "admin",
    role: Role = Role.ADMIN,
    scope_kind: str = "global",
    host_id: int | None = None,
    volume_id: int | None = None,
    mfa_fresh: bool = False,
) -> dict[str, str]:
    """Create a local user with one (role, scope) grant + a session; return a Bearer header.

    Used by API tests to authenticate as an arbitrary principal. The session token is
    returned as an ``Authorization: Bearer`` header (the same opaque token the cookie carries).
    """
    async with db.session_scope() as session:
        user = User(
            subject=username,
            source="local",
            display_name=username,
            password_hash=hash_password("correct horse battery staple"),
            is_active=True,
        )
        session.add(user)
        await session.flush()
        session.add(
            RoleAssignment(
                user_id=user.id,
                role=role.value,
                scope_kind=scope_kind,
                host_id=host_id,
                volume_id=volume_id,
                granted_by="test",
            )
        )
        row, raw = await create_session(session, user_id=user.id, ttl_seconds=3600)
        if mfa_fresh:
            from fathom.auth.sessions import mark_step_up

            await mark_step_up(session, row=row)
    return {"Authorization": f"Bearer {raw}"}
