"""Runtime settings store tests (ADR-038) — overlay, validation, encryption, versioning.

The security-relevant bits: an out-of-range value is rejected before it can persist; secrets are
stored encrypted (never plaintext) and only the explicit reveal path returns them; the effective
settings overlay wins over the base but never leaks the process environment; and a non-editable /
unknown key cannot be set. Persistence + cross-instance reload is exercised against a real SQLite.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fathom.core.catalogue.models import Base
from fathom.core.catalogue.settings_override_meta import SettingsOverride
from fathom.core.settings import Settings
from fathom.core.settings_store import (
    RuntimeSettingsStore,
    SettingsStoreError,
    build_secret_provider,
)

# A fixed key so two store instances in one test can decrypt each other's secrets (durability).
_KEY = Fernet.generate_key().decode("ascii")


@pytest.fixture
async def maker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _base() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///x.db",
        concierge_enabled=False,
        treemap_max_nodes=100,
    )


async def test_no_overrides_returns_base_identity(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    async with maker() as s:
        await store.refresh(s)
    base = _base()
    assert store.effective(base) is base  # zero overrides → the base, untouched


async def test_set_override_wins_and_persists(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()
    async with maker() as s:
        await store.refresh(s)
        await store.set_override(
            s, base=base, key="concierge_enabled", value=True, updated_by="admin"
        )
        await s.commit()
    eff = store.effective(base)
    assert eff.concierge_enabled is True  # in-app value wins
    assert eff.treemap_max_nodes == 100  # untouched base value preserved
    assert eff.database_url == "sqlite+aiosqlite:///x.db"  # env/base never leaked
    assert store.version >= 1


async def test_override_survives_reload_in_a_fresh_store(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    base = _base()
    async with maker() as s:
        writer = RuntimeSettingsStore.from_key_material(_KEY)
        await writer.refresh(s)
        await writer.set_override(
            s, base=base, key="treemap_max_nodes", value=500, updated_by="admin"
        )
        await s.commit()
    # A second store (another worker) reloads from the DB and sees the override.
    reader = RuntimeSettingsStore.from_key_material(_KEY)
    async with maker() as s:
        await reader.refresh(s)
    assert reader.effective(base).treemap_max_nodes == 500


async def test_invalid_value_is_rejected_and_not_persisted(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()
    async with maker() as s:
        await store.refresh(s)
        with pytest.raises(SettingsStoreError):
            # treemap_max_nodes has le=2000 — out of range must be rejected.
            await store.set_override(
                s, base=base, key="treemap_max_nodes", value=999999, updated_by="admin"
            )
        rows = (await s.execute(select(SettingsOverride))).scalars().all()
    assert rows == []  # nothing persisted
    assert store.effective(base).treemap_max_nodes == 100


async def test_unknown_and_non_editable_keys_rejected(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()
    async with maker() as s:
        await store.refresh(s)
        with pytest.raises(SettingsStoreError):
            await store.set_override(s, base=base, key="not_a_setting", value=1, updated_by="a")
        with pytest.raises(SettingsStoreError):
            # database_url has no editable policy (boot-time / not in the allow-list).
            await store.set_override(
                s, base=base, key="database_url", value="sqlite://", updated_by="a"
            )


async def test_secret_setting_is_encrypted_at_rest_and_revealable(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()
    async with maker() as s:
        await store.refresh(s)
        await store.set_override(
            s, base=base, key="ingest_proxy_secret", value="topsecret", updated_by="admin"
        )
        await s.commit()
        row = await s.get(SettingsOverride, "ingest_proxy_secret")
        assert row is not None
        assert row.is_secret is True
        assert "topsecret" not in row.value  # ciphertext, not plaintext
    assert store.reveal("ingest_proxy_secret") == "topsecret"
    # The secret value overlays into the effective settings (the field works live).
    assert store.effective(base).ingest_proxy_secret == "topsecret"


async def test_named_secret_resolves_via_secret_provider(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    async with maker() as s:
        await store.refresh(s)
        await store.set_secret(s, ref="ANTHROPIC_KEY", value="sk-ant-123", updated_by="admin")
        await s.commit()
    # The store sits in front of the env/Docker fallback (which must NOT be consulted here).
    def _boom(ref: str) -> str:  # pragma: no cover - must not be called
        raise AssertionError("fallback should not run for an in-app secret")

    provider = build_secret_provider(store, _boom)
    assert provider("ANTHROPIC_KEY") == "sk-ant-123"
    # A secret the store does not hold falls through to the fallback.
    provider2 = build_secret_provider(store, lambda ref: f"env:{ref}")
    assert provider2("OTHER") == "env:OTHER"
    # Named secrets are listed (names only) and never appear as Settings fields.
    assert store.list_named_secrets() == ["ANTHROPIC_KEY"]


async def test_set_secret_rejects_a_settings_field_name(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    async with maker() as s:
        await store.refresh(s)
        with pytest.raises(SettingsStoreError):
            await store.set_secret(s, ref="concierge_enabled", value="x", updated_by="a")


async def test_clear_override_resets_to_default(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()
    async with maker() as s:
        await store.refresh(s)
        await store.set_override(
            s, base=base, key="concierge_enabled", value=True, updated_by="admin"
        )
        await s.commit()
        assert store.effective(base).concierge_enabled is True
        hit = await store.clear_override(s, key="concierge_enabled")
        await s.commit()
    assert hit is True
    assert store.effective(base).concierge_enabled is False  # back to the base default
    # Clearing a key with no override returns False.
    async with maker() as s:
        assert await store.clear_override(s, key="concierge_enabled") is False


async def test_reveal_rejects_a_non_secret(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()
    async with maker() as s:
        await store.refresh(s)
        await store.set_override(
            s, base=base, key="treemap_max_nodes", value=200, updated_by="admin"
        )
        await s.commit()
    with pytest.raises(SettingsStoreError):
        store.reveal("treemap_max_nodes")  # not a secret


async def test_list_settings_masks_secrets(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()
    async with maker() as s:
        await store.refresh(s)
        await store.set_override(
            s, base=base, key="ingest_proxy_secret", value="hush", updated_by="admin"
        )
        await s.commit()
    views = {v.key: v for v in store.list_settings(base)}
    secret_view = views["ingest_proxy_secret"]
    assert secret_view.is_secret is True
    assert secret_view.value is None  # never exposed in the list
    assert secret_view.is_set is True
    # A non-secret setting exposes its effective value.
    assert views["treemap_max_nodes"].value == 100


async def test_list_settings_labels_options_and_relevance(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    async with maker() as s:
        await store.refresh(s)

    ollama = Settings(database_url="sqlite+aiosqlite:///x.db", inference_provider="ollama")
    views = {v.key: v for v in store.list_settings(ollama)}
    # Human label override + auto-humanised fallback for an unlabelled key.
    assert views["inference_provider"].label == "Inference provider"
    assert views["inference_provider"].options == ["ollama", "openai", "anthropic"]
    assert views["treemap_max_nodes"].label == "Treemap Max Nodes"
    # provider=ollama → the anthropic + openai settings are inapplicable, with a hint.
    assert views["inference_anthropic_key_ref"].relevant is False
    assert "anthropic" in (views["inference_anthropic_key_ref"].relevant_hint or "").lower()
    assert views["inference_openai_key_ref"].relevant is False
    # Always-relevant settings have no gate.
    assert views["inference_provider"].relevant is True
    # Provider-dependent model picker: Ollama can run anything → free-text combobox (suggestions),
    # no strict option set. The Ollama URL applies; the cloud egress gate does not.
    assert views["inference_model"].options is None
    assert views["inference_model"].suggestions == ["llama3.2:3b", "llama3.1:8b"]
    assert views["inference_ollama_url"].relevant is True
    assert views["inference_allow_egress"].relevant is False
    # Embedding provider tracks the chat provider: Ollama chat → only the local embedder.
    assert views["concierge_embedding_provider"].options == ["ollama"]

    # Switch the provider → anthropic settings become relevant, openai stays inapplicable.
    anthropic = Settings(database_url="sqlite+aiosqlite:///x.db", inference_provider="anthropic")
    v2 = {v.key: v for v in store.list_settings(anthropic)}
    assert v2["inference_anthropic_key_ref"].relevant is True
    assert v2["inference_openai_key_ref"].relevant is False
    # Anthropic chat → a strict dropdown of current Claude model IDs (no free-text suggestions).
    assert v2["inference_model"].options is not None
    assert "claude-opus-4-8" in v2["inference_model"].options
    assert v2["inference_model"].suggestions is None
    # Ollama URL now hidden; cloud egress gate now applies.
    assert v2["inference_ollama_url"].relevant is False
    assert v2["inference_allow_egress"].relevant is True
    # Voyage is Anthropic's recommended embedder; local Ollama stays available.
    assert v2["concierge_embedding_provider"].options == ["voyage", "ollama"]


async def test_key_ref_rejects_a_pasted_raw_key(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    # A user pasting the actual API key into a *_key_ref field is the footgun (ADR-010): the value
    # is a reference NAME, not the key. Reject obvious raw keys so they never land unencrypted.
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()
    async with maker() as s:
        await store.refresh(s)
        with pytest.raises(SettingsStoreError, match="reference NAME"):
            await store.set_override(
                s,
                base=base,
                key="inference_anthropic_key_ref",
                value="sk-ant-api03-abcDEF123456",
                updated_by="admin",
            )
        # A long opaque token (no sk- prefix) is caught too.
        with pytest.raises(SettingsStoreError, match="reference NAME"):
            await store.set_override(
                s,
                base=base,
                key="inference_anthropic_key_ref",
                value="x" * 80,
                updated_by="admin",
            )
        # A real reference name is accepted.
        await store.set_override(
            s,
            base=base,
            key="inference_anthropic_key_ref",
            value="ANTHROPIC_KEY",
            updated_by="admin",
        )
        await s.commit()
    assert store.effective(base).inference_anthropic_key_ref == "ANTHROPIC_KEY"


async def test_direct_api_key_is_encrypted_and_usable(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    # The easy path the user wants: paste the key into a masked field → stored encrypted → used
    # directly (no reference indirection). The *_api_key fields are secret settings.
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()
    async with maker() as s:
        await store.refresh(s)
        await store.set_override(
            s,
            base=base,
            key="inference_anthropic_api_key",
            value="sk-ant-realkey123",
            updated_by="admin",
        )
        await s.commit()
        row = await s.get(SettingsOverride, "inference_anthropic_api_key")
        assert row is not None
        assert row.is_secret is True
        assert "sk-ant-realkey123" not in row.value  # ciphertext, not plaintext
    assert store.reveal("inference_anthropic_api_key") == "sk-ant-realkey123"
    assert store.effective(base).inference_anthropic_api_key == "sk-ant-realkey123"


async def test_api_key_fields_are_secret_and_refs_are_advanced(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    store = RuntimeSettingsStore.from_key_material(_KEY)
    async with maker() as s:
        await store.refresh(s)
    base = Settings(database_url="sqlite+aiosqlite:///x.db", inference_provider="anthropic")
    views = {v.key: v for v in store.list_settings(base)}
    # Direct key: a masked secret field, shown by default (the easy path).
    assert views["inference_anthropic_api_key"].is_secret is True
    assert views["inference_anthropic_api_key"].advanced is False
    assert views["inference_anthropic_api_key"].label == "Anthropic API key"
    # The legacy secret-backend reference is demoted to "advanced".
    assert views["inference_anthropic_key_ref"].advanced is True
    assert views["inference_openai_key_ref"].advanced is True
    assert views["concierge_embedding_key_ref"].advanced is True


async def test_build_secret_provider_without_store_is_passthrough() -> None:
    provider = build_secret_provider(None, lambda ref: f"env:{ref}")
    assert provider("X") == "env:X"


async def test_switching_provider_resets_inference_model_to_provider_default(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    # Cohesion (P1): switching the chat provider resets the shared inference_model to the new
    # provider's default, so a model from the old provider (e.g. an Ollama tag on Anthropic) can't
    # linger and 404 the cloud API.
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()  # default provider=ollama, inference_model=llama3.2:3b
    async with maker() as s:
        await store.refresh(s)
        await store.set_override(
            s, base=base, key="inference_model", value="llama3.1:8b", updated_by="a"
        )
        await s.commit()
        assert store.effective(base).inference_model == "llama3.1:8b"
        await store.set_override(
            s, base=base, key="inference_provider", value="anthropic", updated_by="a"
        )
        await s.commit()
    eff = store.effective(base)
    assert eff.inference_provider == "anthropic"
    assert eff.inference_model == "claude-haiku-4-5"  # reset to the anthropic default


async def test_resaving_same_provider_keeps_inference_model(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    # A no-op re-save of the SAME provider must NOT clobber a deliberately-chosen model.
    store = RuntimeSettingsStore.from_key_material(_KEY)
    base = _base()
    async with maker() as s:
        await store.refresh(s)
        await store.set_override(
            s, base=base, key="inference_provider", value="anthropic", updated_by="a"
        )
        await s.commit()
        await store.set_override(
            s, base=base, key="inference_model", value="claude-opus-4-8", updated_by="a"
        )
        await s.commit()
        await store.set_override(
            s, base=base, key="inference_provider", value="anthropic", updated_by="a"
        )
        await s.commit()
    assert store.effective(base).inference_model == "claude-opus-4-8"  # preserved


async def test_secret_under_a_prior_key_is_skipped_not_fatal(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    # A secret row encrypted under a PRIOR Fernet key (e.g. an ephemeral key from a previous boot)
    # can't be decrypted by the current store → the row is skipped (degrade to the env base) with a
    # warn-once, never a fatal refresh. (EC-settings-15)
    other_key = Fernet.generate_key().decode("ascii")
    writer = RuntimeSettingsStore.from_key_material(other_key)
    async with maker() as s:
        await writer.refresh(s)
        await writer.set_secret(s, ref="ANTHROPIC_KEY", value="sk-ant-prior", updated_by="admin")
        await s.commit()
    # A store holding a DIFFERENT key reloads the same DB.
    reader = RuntimeSettingsStore.from_key_material(_KEY)
    async with maker() as s:
        await reader.refresh(s)
        await reader.refresh(s)  # twice → warn-once: the second refresh must not re-warn
    # The undecodable secret is dropped, not surfaced — and the refresh never raised.
    assert reader.list_named_secrets() == []
    assert reader.resolve_secret("ANTHROPIC_KEY") is None
    with pytest.raises(SettingsStoreError):
        reader.reveal("ANTHROPIC_KEY")
    assert reader.version == 1  # the (non-secret) version row still loaded fine
    # Warn-once asserted via the store's OWN dedup state, not log capture: the store warns about an
    # undecodable key exactly when it first adds that key to `_warned_undecodable`, so after two
    # refreshes the set holds the key exactly once (a second warning would require it to be absent).
    # This is deterministic regardless of global logging config (a prior test can disable/retarget
    # the logger, which silently starved the earlier caplog-based assertion in the full suite).
    assert reader._warned_undecodable == {"ANTHROPIC_KEY"}


async def test_two_writers_last_writer_wins_version_monotonic(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    # Two store instances writing the same key in turn: the last write wins and the version is
    # monotonic across both. (aiosqlite serializes writers, so this exercises the serialized
    # last-writer-wins contract rather than OS-level parallelism.) (EC-settings-16)
    base = _base()
    w1 = RuntimeSettingsStore.from_key_material(_KEY)
    w2 = RuntimeSettingsStore.from_key_material(_KEY)
    async with maker() as s:
        await w1.refresh(s)
        await w1.set_override(s, base=base, key="treemap_max_nodes", value=111, updated_by="w1")
        await s.commit()
    v1 = w1.version
    async with maker() as s:
        await w2.refresh(s)
        await w2.set_override(s, base=base, key="treemap_max_nodes", value=222, updated_by="w2")
        await s.commit()
    v2 = w2.version
    assert v1 == 1 and v2 == 2 and v2 > v1  # strictly monotonic
    # A fresh reader sees only the last write — and exactly one row (upsert, not stacked).
    reader = RuntimeSettingsStore.from_key_material(_KEY)
    async with maker() as s:
        await reader.refresh(s)
        rows = (
            await s.execute(
                select(SettingsOverride).where(SettingsOverride.key == "treemap_max_nodes")
            )
        ).scalars().all()
    assert len(rows) == 1  # the second writer overwrote the row, didn't insert a duplicate
    assert reader.effective(base).treemap_max_nodes == 222  # last writer wins


async def test_refresh_tolerates_missing_tables() -> None:
    # A DB without the settings tables (e.g. a non-schema test) must not raise — the store just
    # falls back to the env base with no overrides.
    engine = create_async_engine("sqlite+aiosqlite://")
    maker = async_sessionmaker(engine, expire_on_commit=False)
    store = RuntimeSettingsStore.from_key_material(_KEY)
    async with maker() as s:
        await store.refresh(s)
    assert store.version == 0
    assert store.effective(_base()).concierge_enabled is False
    await engine.dispose()
