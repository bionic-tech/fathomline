"""Concierge route tests (ADR-035) — the default-OFF gate, scope, and a fake-provider answer.

The route is read-only and gated by ``concierge_enabled`` + ``VIEW_METADATA`` + scope. A fake
provider stands in for the LLM (the route never reaches a real model), returning a canned intent +
answer so the end-to-end classify→query→narrate path can be asserted deterministically.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from asgi_lifespan import LifespanManager
from pydantic import BaseModel

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.concierge.service import ConciergeAnswer, ConciergeIntent, ConciergeTool
from fathom.core.settings import Settings
from fathom.inference import InferenceError
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal


class _FakeProvider:
    """Canned classify intent + narrate answer — stands in for the LLM in the route test."""

    def __init__(self, intent: ConciergeIntent, answer: str = "Found it.") -> None:
        self._intent = intent
        self._answer = answer

    async def complete(self, *, system: str, user: str, schema: type[BaseModel]) -> BaseModel:
        if schema is ConciergeIntent:
            return self._intent
        return ConciergeAnswer(answer=self._answer)


def _patch_provider(monkeypatch: pytest.MonkeyPatch, provider: object) -> None:
    monkeypatch.setattr(
        "fathom.api.routers.concierge.build_inference_provider",
        lambda _s, *, model=None, secret_provider=None: provider,
    )


@pytest.fixture
async def concierge_client(tmp_path: object) -> AsyncIterator[httpx.AsyncClient]:
    """A client whose app has the concierge enabled (the default app keeps it OFF)."""
    await db.dispose_engine()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/cat.db",  # type: ignore[attr-defined]
        auto_create_schema=True,
        session_cookie_secure=False,
        concierge_enabled=True,
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


@pytest.fixture
async def concierge_embeddings_client(tmp_path: object) -> AsyncIterator[httpx.AsyncClient]:
    """Concierge enabled WITH semantic embeddings on (so the embedder-build path is exercised)."""
    await db.dispose_engine()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/cat.db",  # type: ignore[attr-defined]
        auto_create_schema=True,
        session_cookie_secure=False,
        concierge_enabled=True,
        concierge_embeddings_enabled=True,
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


async def test_ask_disabled_by_default(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal()
    resp = await api_client.post(
        "/api/v1/concierge/ask", json={"question": "where is a.mkv?"}, headers=auth
    )
    assert resp.status_code == 403  # concierge_enabled=False on the default app


async def test_ask_requires_auth(concierge_client: httpx.AsyncClient) -> None:
    resp = await concierge_client.post(
        "/api/v1/concierge/ask", json={"question": "where is a.mkv?"}
    )
    assert resp.status_code == 401  # no principal


async def test_ask_returns_answer(
    concierge_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_provider(
        monkeypatch,
        _FakeProvider(ConciergeIntent(tool=ConciergeTool.FIND_FILE, name_or_fragment="a.mkv")),
    )
    await concierge_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    auth = await seed_principal()
    resp = await concierge_client.post(
        "/api/v1/concierge/ask", json={"question": "where is a.mkv?"}, headers=auth
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tool"] == "find_file"
    assert body["answer"] == "Found it."
    assert any(c["path"] == "/mnt/pool/movies/a.mkv" for c in body["citations"])


async def test_ask_out_of_scope_volume_403(
    concierge_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EC-concierge-3: an EXISTING volume hint outside the principal's scope is 403.

    The volume exists (so its existence is already known to the estate), the principal just may not
    see it — `get_volume_in_scope` raises 403. Distinct from a NONEXISTENT hint (404, below).
    """
    _patch_provider(
        monkeypatch,
        _FakeProvider(ConciergeIntent(tool=ConciergeTool.FIND_FILE, name_or_fragment="a")),
    )
    r = await concierge_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    vol = r.json()["volume_id"]
    scoped = await seed_principal(username="scoped", scope_kind="volume", volume_id=vol + 999)
    resp = await concierge_client.post(
        "/api/v1/concierge/ask",
        json={"question": "find a", "volume_id": vol},
        headers=scoped,
    )
    assert resp.status_code == 403  # the volume hint is out of this principal's scope


async def test_ask_nonexistent_volume_404(concierge_client: httpx.AsyncClient) -> None:
    """EC-concierge-3: a NONEXISTENT volume hint is 404 (vs out-of-scope 403, above).

    A global admin (in scope for everything) supplying a volume id that does not exist gets 404
    'unknown volume' — the absent-vs-forbidden boundary, fired before any provider build.
    """
    auth = await seed_principal()  # global admin → in scope for everything
    resp = await concierge_client.post(
        "/api/v1/concierge/ask",
        json={"question": "find a", "volume_id": 999999},
        headers=auth,
    )
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "unknown volume"


async def test_ask_inference_error_is_mapped(
    concierge_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(_s: object, *, model: str | None = None, secret_provider: object = None) -> object:
        raise InferenceError("provider down", status_code=503)

    monkeypatch.setattr("fathom.api.routers.concierge.build_inference_provider", _boom)
    auth = await seed_principal()
    resp = await concierge_client.post(
        "/api/v1/concierge/ask", json={"question": "anything"}, headers=auth
    )
    assert resp.status_code == 503  # sanitised mapping, no provider internals leaked
    assert resp.json()["detail"] == "inference unavailable"


async def test_ask_inference_timeout_maps_504(
    concierge_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A provider/classify timeout surfaces as InferenceError(status_code=504); the route propagates
    # 504 verbatim (the web layer shows a distinct "took too long" copy) — not a generic 500.
    def _timeout(_s: object, *, model: str | None = None, secret_provider: object = None) -> object:
        raise InferenceError("upstream timed out", status_code=504)

    monkeypatch.setattr("fathom.api.routers.concierge.build_inference_provider", _timeout)
    auth = await seed_principal()
    resp = await concierge_client.post(
        "/api/v1/concierge/ask", json={"question": "anything"}, headers=auth
    )
    assert resp.status_code == 504
    assert resp.json()["detail"] == "inference unavailable"


async def test_ask_unknown_forced_tool_422(concierge_client: httpx.AsyncClient) -> None:
    # A /command may force a tool; an unknown one is rejected 422 (closed enum), never a silent
    # fallback to LLM classification. The 422 fires before any provider build, so no mock needed.
    auth = await seed_principal()
    resp = await concierge_client.post(
        "/api/v1/concierge/ask",
        json={"question": "do the thing", "tool": "definitely_not_a_tool"},
        headers=auth,
    )
    assert resp.status_code == 422
    assert "unknown concierge tool" in resp.json()["detail"]


@pytest.mark.parametrize(
    "bad_body",
    [
        {"question": ""},  # empty question violates min_length=1
        {"question": "ok", "volume_id": 0},  # volume_id below ge=1
        {"question": "ok", "page": "x" * 65},  # page hint over max_length=64
        {"question": "ok", "history": [{"role": "user", "content": "h"}] * 21},  # >20 turns
    ],
    ids=["empty-question", "volume-id-zero", "page-too-long", "history-too-long"],
)
async def test_ask_invalid_body_422(
    concierge_client: httpx.AsyncClient, bad_body: dict
) -> None:
    # EC-concierge-5: schema validation (Pydantic) rejects malformed bodies with 422 before any
    # tool runs — the request never reaches the LLM/classify path. Authenticated so we exercise body
    # validation (not the 401), and no provider mock is needed (the 422 fires first).
    auth = await seed_principal()
    resp = await concierge_client.post("/api/v1/concierge/ask", json=bad_body, headers=auth)
    assert resp.status_code == 422, resp.text


async def test_ask_inference_bad_output_maps_502(
    concierge_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # EC-concierge-7: a provider that answered but whose output failed schema validation raises
    # InferenceError(status_code=502); the route maps the status verbatim (502 ≠ the 503 "down"
    # case), still with the sanitised detail and no provider internals leaked.
    def _bad(_s: object, *, model: str | None = None, secret_provider: object = None) -> object:
        raise InferenceError("unparseable model output", status_code=502)

    monkeypatch.setattr("fathom.api.routers.concierge.build_inference_provider", _bad)
    auth = await seed_principal()
    resp = await concierge_client.post(
        "/api/v1/concierge/ask", json={"question": "anything"}, headers=auth
    )
    assert resp.status_code == 502
    assert resp.json()["detail"] == "inference unavailable"


async def test_ask_out_of_scope_host_returns_empty(
    concierge_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EC-concierge-21: a volume-scoped principal asks (host_id hint) about a host OUT of its scope.

    The route 403s an out-of-scope *volume* hint, but a *host* hint is not pre-checked — instead
    every query fail-closes on the server-authoritative ScopeFilter, so the intersection (the
    principal's volume ∩ the other host) is empty. The answer is a benign 200 with zero rows / zero
    citations — never an error and never a leak that the other host even exists.
    """
    _patch_provider(
        monkeypatch, _FakeProvider(ConciergeIntent(tool=ConciergeTool.FLEET_STORAGE))
    )
    r1 = await concierge_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    vol1 = r1.json()["volume_id"]  # the volume the principal IS scoped to (host nas-1)
    # A SECOND host (distinct name + cert fingerprint) entirely outside the principal's scope.
    r2 = await concierge_client.post(
        "/api/v1/agents/ingest",
        json=batch(
            host={"name": "nas-2", "os": "TrueNAS", "agent_version": "0.1.0"},
            mountpoint="/mnt/other",
        ),
        headers={"X-Client-Cert-Fingerprint": "11:22:33:44"},
    )
    host2 = r2.json()["host_id"]
    scoped = await seed_principal(username="vscoped", scope_kind="volume", volume_id=vol1)
    resp = await concierge_client.post(
        "/api/v1/concierge/ask",
        json={"question": "how full is nas-2?", "host_id": host2},
        headers=scoped,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["considered"] == 0  # the out-of-scope host contributes nothing
    assert body["citations"] == []


async def test_ask_embedder_build_failure_degrades_to_substring(
    concierge_embeddings_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # EC-concierge-15: embeddings ON but the embedder BUILD fails (e.g. a cloud embedder without
    # egress/key). The route swallows that InferenceError → embedding_provider=None, and a
    # semantic_search degrades to the substring find. The ask still succeeds (200) with grounded
    # citations — a build failure must never turn into a 5xx.
    client = concierge_embeddings_client
    _patch_provider(
        monkeypatch,
        _FakeProvider(
            ConciergeIntent(tool=ConciergeTool.SEMANTIC_SEARCH, name_or_fragment="a.mkv")
        ),
    )

    def _embed_boom(_s: object, *, secret_provider: object = None) -> object:
        raise InferenceError("cloud embedding disabled without egress", status_code=503)

    monkeypatch.setattr("fathom.api.routers.concierge.build_embedding_provider", _embed_boom)
    await client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    auth = await seed_principal()
    resp = await client.post(
        "/api/v1/concierge/ask", json={"question": "find the a.mkv file"}, headers=auth
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["tool"] == "semantic_search"  # the chosen tool is still reported as semantic_search
    # The substring fallback found the real row, so the citation is grounded (not empty / not 5xx).
    assert any(c["path"] == "/mnt/pool/movies/a.mkv" for c in body["citations"])
