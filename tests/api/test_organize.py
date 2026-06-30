"""Organize suggestion tests (ADR-021) — the path-clamp firewall + the read-only route.

The security core is :func:`clamp_to_root` and the service's per-item validation: a prompt-injected
or hostile model proposal can only ever yield an in-root suggestion, never a move outside the
folder. These tests drive the service with a fake provider returning hostile proposals and assert
every escape is rejected. Nothing here touches the filesystem.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from asgi_lifespan import LifespanManager

from fathom.api.app import create_app
from fathom.core import db
from fathom.core.organize.service import (
    OrganizeService,
    _Assignment,
    _LlmProposal,
    clamp_to_root,
)
from fathom.core.settings import Settings
from tests.api.conftest import FINGERPRINT_HEADER, batch, seed_principal


class _FakeProvider:
    """Returns a canned ``_LlmProposal`` — stands in for the LLM so tests are deterministic."""

    def __init__(self, proposal: _LlmProposal) -> None:
        self._proposal = proposal

    async def complete(self, *, system: str, user: str, schema: object) -> _LlmProposal:
        return self._proposal


# --- clamp_to_root: the firewall ---------------------------------------------------------


def test_clamp_accepts_in_root() -> None:
    assert clamp_to_root("/mnt/pool", "a/b.txt") == "/mnt/pool/a/b.txt"
    assert clamp_to_root("/mnt/pool", "ok") == "/mnt/pool/ok"
    assert clamp_to_root("/mnt/pool", "a/./b") == "/mnt/pool/a/b"
    assert clamp_to_root("/mnt/pool/", "x") == "/mnt/pool/x"  # trailing slash on root


@pytest.mark.parametrize(
    "rel",
    [
        "",  # empty
        "/etc/passwd",  # absolute
        "../etc",  # parent escape
        "../../etc/passwd",  # deep escape
        "a/../../b",  # escapes after normalisation
        "a/\x00b",  # NUL byte
    ],
)
def test_clamp_rejects_escapes(rel: str) -> None:
    assert clamp_to_root("/mnt/pool", rel) is None


# --- service: hostile proposals are clamped, never escape --------------------------------


async def _seed_files(api_client: httpx.AsyncClient) -> int:
    resp = await api_client.post("/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER)
    return resp.json()["volume_id"]


async def _suggest(volume_id: int, proposal: _LlmProposal) -> dict[str, str]:
    """Run the service against the seeded catalogue with a fake provider; return name->status."""
    async with db.session_scope() as session:
        svc = OrganizeService(session, _FakeProvider(proposal), model="fake")
        result = await svc.suggest(volume_id=volume_id, root="/mnt/pool")
    return {it.current_name: it.status for it in result.items}


async def test_traversal_target_is_rejected(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_files(api_client)
    # The model tries to move every file out of the root — all must be rejected, none "move".
    proposal = _LlmProposal(
        assignments=[
            _Assignment(index=i, target_dir="../../../etc", new_name="pwned") for i in range(3)
        ]
    )
    statuses = await _suggest(vol, proposal)
    assert statuses  # the three seeded files were considered
    assert all(s == "rejected" for s in statuses.values())


async def test_absolute_and_bad_name_rejected(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_files(api_client)
    proposal = _LlmProposal(
        assignments=[
            _Assignment(index=0, target_dir="/etc", new_name="passwd"),  # absolute → reject
            _Assignment(index=1, target_dir="ok", new_name="../evil"),  # bad leaf → reject
            _Assignment(index=2, target_dir="media", new_name="clip.mkv"),  # benign → move
        ]
    )
    statuses = await _suggest(vol, proposal)
    assert sorted(statuses.values()) == ["move", "rejected", "rejected"]


async def test_collision_second_rejected(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_files(api_client)
    # Two files proposed to the exact same target → the second is rejected (no silent merge).
    proposal = _LlmProposal(
        assignments=[
            _Assignment(index=0, target_dir="all", new_name="same.bin"),
            _Assignment(index=1, target_dir="all", new_name="same.bin"),
            _Assignment(index=2, target_dir="all", new_name="other.bin"),
        ]
    )
    result_statuses = list((await _suggest(vol, proposal)).values())
    assert result_statuses.count("move") == 2  # one of the colliders + the distinct one
    assert result_statuses.count("rejected") == 1


async def test_benign_proposal_moves(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_files(api_client)
    proposal = _LlmProposal(
        assignments=[_Assignment(index=i, target_dir="sorted") for i in range(3)]
    )
    async with db.session_scope() as session:
        svc = OrganizeService(session, _FakeProvider(proposal), model="fake")
        result = await svc.suggest(volume_id=vol, root="/mnt/pool")
    moves = [it for it in result.items if it.status == "move"]
    assert len(moves) == 3
    assert all(it.proposed_relpath.startswith("sorted/") for it in moves)
    assert result.rejected == 0


# --- few-shot learning from applied plans (ADR-021 Phase 3) ------------------------------


class _CapturingProvider:
    """Records the user prompt it is handed, then returns a canned proposal."""

    def __init__(self, proposal: _LlmProposal) -> None:
        self._proposal = proposal
        self.last_user = ""

    async def complete(self, *, system: str, user: str, schema: object) -> _LlmProposal:
        self.last_user = user
        return self._proposal


async def _persist_executed_move(volume_id: int, *, path: str, dest_rel: str, status: str) -> None:
    from fathom.core.remediation.models import RemediationPlanItemRow, RemediationPlanRow

    async with db.session_scope() as session:
        row = RemediationPlanRow(
            plan_id=f"org-{path.rsplit('/', 1)[-1]}-{status}",
            created_by="mo",
            host_id="1",
            volume_id=volume_id,
            keeper_path="/mnt/pool",
            status=status,
            blast_count=1,
            move_root="/mnt/pool",
        )
        row.items = [
            RemediationPlanItemRow(
                entry_id=1, path=path, prior_inode=1, prior_size=1, action="move", dest_rel=dest_rel
            )
        ]
        session.add(row)
        await session.flush()


async def test_fewshot_seeds_prompt_from_executed_moves(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_files(api_client)
    # An APPLIED (executed) move on this volume becomes a few-shot example...
    await _persist_executed_move(
        vol, path="/mnt/pool/movies/a.mkv", dest_rel="videos/a.mkv", status="executed"
    )
    # ...while a merely-built (un-applied) plan must NOT leak into the prompt.
    await _persist_executed_move(
        vol, path="/mnt/pool/docs/secret.txt", dest_rel="private/secret.txt", status="built"
    )
    cap = _CapturingProvider(_LlmProposal())
    async with db.session_scope() as session:
        svc = OrganizeService(session, cap, model="fake")
        await svc.suggest(volume_id=vol, root="/mnt/pool")
    assert "previously organised" in cap.last_user
    assert "a.mkv  ->  videos/a.mkv" in cap.last_user  # learned the applied move
    assert "secret.txt" not in cap.last_user  # the un-applied plan never leaks


async def test_fewshot_absent_without_history(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_files(api_client)
    cap = _CapturingProvider(_LlmProposal())
    async with db.session_scope() as session:
        svc = OrganizeService(session, cap, model="fake")
        await svc.suggest(volume_id=vol, root="/mnt/pool")
    assert "previously organised" not in cap.last_user  # nothing learned yet → no example block


# --- route: default-OFF gate + scope -----------------------------------------------------


@pytest.fixture
async def organize_client(tmp_path: object) -> AsyncIterator[httpx.AsyncClient]:
    """A client whose app has organize enabled (the default app keeps it OFF)."""
    await db.dispose_engine()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/cat.db",  # type: ignore[attr-defined]
        auto_create_schema=True,
        session_cookie_secure=False,
        organize_enabled=True,
    )
    app = create_app(settings)
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    await db.dispose_engine()


async def test_suggest_disabled_by_default(api_client: httpx.AsyncClient) -> None:
    vol = await _seed_files(api_client)
    auth = await seed_principal()
    resp = await api_client.post(
        "/api/v1/organize/suggest", json={"volume_id": vol, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 403  # organize_enabled=False on the default app


async def test_suggest_enabled_returns_proposal(
    organize_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Inject the fake provider so the route never reaches a real model.
    proposal = _LlmProposal(assignments=[_Assignment(index=i, target_dir="tidy") for i in range(3)])
    monkeypatch.setattr(
        "fathom.api.routers.organize.build_inference_provider",
        lambda _s, *, model=None, secret_provider=None: _FakeProvider(proposal),
    )
    r = await organize_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    vol = r.json()["volume_id"]
    auth = await seed_principal()
    resp = await organize_client.post(
        "/api/v1/organize/suggest", json={"volume_id": vol, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["considered"] == 3
    assert all(it["proposed_relpath"].startswith("tidy/") for it in body["items"])


async def test_suggest_out_of_scope_403(
    organize_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "fathom.api.routers.organize.build_inference_provider",
        lambda _s, *, model=None, secret_provider=None: _FakeProvider(_LlmProposal()),
    )
    r = await organize_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    vol = r.json()["volume_id"]
    scoped = await seed_principal(username="scoped", scope_kind="volume", volume_id=vol + 999)
    resp = await organize_client.post(
        "/api/v1/organize/suggest", json={"volume_id": vol, "path": "/mnt/pool"}, headers=scoped
    )
    assert resp.status_code == 403


async def test_suggest_nonexistent_volume_404(
    organize_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EC-organize-ai-25: a NONEXISTENT volume is 404 (vs out-of-scope 403, above).

    A global admin (in scope for everything) requesting a volume id that does not exist must get
    404 'unknown volume' — the absent-vs-forbidden boundary `get_volume_in_scope` draws: None for
    absent (404), raise for out-of-scope (403). The 404 fires before any provider build.
    """
    monkeypatch.setattr(
        "fathom.api.routers.organize.build_inference_provider",
        lambda _s, *, model=None, secret_provider=None: _FakeProvider(_LlmProposal()),
    )
    r = await organize_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    vol = r.json()["volume_id"]
    auth = await seed_principal()  # global admin → in scope for everything
    resp = await organize_client.post(
        "/api/v1/organize/suggest",
        json={"volume_id": vol + 999, "path": "/mnt/pool"},
        headers=auth,
    )
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "unknown volume"


async def test_activity_nonexistent_volume_404(organize_client: httpx.AsyncClient) -> None:
    """A global admin asking for activity on an absent volume → 404 (not 403)."""
    auth = await seed_principal()
    resp = await organize_client.get(
        "/api/v1/organize/activity",
        params={"volume_id": 999999, "path": "/mnt/pool"},
        headers=auth,
    )
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"] == "unknown volume"


async def test_activity_out_of_scope_403(organize_client: httpx.AsyncClient) -> None:
    """An existing volume the principal can't see → 403 (existence acknowledged, access denied)."""
    r = await organize_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    vol = r.json()["volume_id"]
    scoped = await seed_principal(username="scopedact", scope_kind="volume", volume_id=vol + 999)
    resp = await organize_client.get(
        "/api/v1/organize/activity",
        params={"volume_id": vol, "path": "/mnt/pool"},
        headers=scoped,
    )
    assert resp.status_code == 403


# --- watch trigger off the change feed (ADR-021 Phase 3) ---------------------------------


async def _seed_volume_with_changes(rows: list[tuple[str, str]]) -> int:
    """Create a host+volume at /mnt/pool with a controlled change feed (NO ingest pollution).

    Seeding the volume directly (rather than via /agents/ingest, whose first scan logs a 'create'
    per file) keeps the change_log exactly what the test inserts. Returns the volume id.
    """
    from fathom.core.catalogue.models import ChangeLog, Host, Volume

    async with db.session_scope() as session:
        host = Host(name="nas-1", cert_fingerprint="ab:cd")
        session.add(host)
        await session.flush()
        volume = Volume(
            host_id=host.id, mountpoint="/mnt/pool", fs_type="zfs", device="tank", transport="sata"
        )
        session.add(volume)
        await session.flush()
        for path, change_type in rows:
            session.add(ChangeLog(volume_id=volume.id, path=path, change_type=change_type))
        await session.flush()
        return volume.id


async def test_activity_counts_recent_churn(organize_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume_with_changes(
        [
            ("/mnt/pool/movies/new1.mkv", "create"),
            ("/mnt/pool/movies/new2.mkv", "create"),
            ("/mnt/pool/docs/notes.txt", "modify"),  # under docs/, not movies/ → excluded
            ("/mnt/pool/movies/old.mkv", "delete"),
            ("/elsewhere/x.bin", "create"),  # outside the volume root → must not count
        ]
    )
    auth = await seed_principal()
    resp = await organize_client.get(
        "/api/v1/organize/activity",
        params={"volume_id": vol, "path": "/mnt/pool/movies"},
        headers=auth,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["created"] == 2
    assert body["deleted"] == 1
    assert body["modified"] == 0  # the modify was under docs/, not movies/
    assert body["suggests_reorganise"] is True  # new files appeared


async def test_activity_quiet_folder_no_nudge(organize_client: httpx.AsyncClient) -> None:
    vol = await _seed_volume_with_changes([("/mnt/pool/movies/gone.mkv", "delete")])
    auth = await seed_principal()
    resp = await organize_client.get(
        "/api/v1/organize/activity",
        params={"volume_id": vol, "path": "/mnt/pool"},
        headers=auth,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["created"] == 0 and body["modified"] == 0
    assert body["suggests_reorganise"] is False  # pure deletions are not a re-organise nudge


async def test_activity_disabled_by_default(api_client: httpx.AsyncClient) -> None:
    auth = await seed_principal()
    resp = await api_client.get(
        "/api/v1/organize/activity",
        params={"volume_id": 1, "path": "/mnt/pool"},
        headers=auth,
    )
    assert resp.status_code == 403  # organize_enabled=False on the default app (gate before lookup)


# --- coverage close: auth, inference-error mapping, empty-folder short-circuit, param matrix ----


class _NeverCalledProvider:
    """Fails the test if asked to complete — proves the read path short-circuited first."""

    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, *, system: str, user: str, schema: object) -> _LlmProposal:
        self.calls += 1
        raise AssertionError("provider.complete must not be called")


class _InferenceErrorProvider:
    """Raises a typed InferenceError on complete — drives the route's sanitised status mapping."""

    def __init__(self, status_code: int) -> None:
        self._status = status_code

    async def complete(self, *, system: str, user: str, schema: object) -> _LlmProposal:
        from fathom.inference import InferenceError

        raise InferenceError("model blew up", status_code=self._status)


async def test_suggest_without_session_401(organize_client: httpx.AsyncClient) -> None:
    """EC-organize-ai-12: no session → 401 (deny-by-default at the auth dep, before any gate)."""
    resp = await organize_client.post(
        "/api/v1/organize/suggest", json={"volume_id": 1, "path": "/mnt/pool"}
    )
    assert resp.status_code == 401, resp.text


async def test_suggest_inference_error_maps_504(
    organize_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EC-organize-ai-18: an InferenceError(504) is mapped to 504 with a sanitised detail.

    The route surfaces ``exc.status_code`` verbatim (not a fixed 503) and replaces the message with
    the constant "inference unavailable" so no provider internals leak.
    """
    monkeypatch.setattr(
        "fathom.api.routers.organize.build_inference_provider",
        lambda _s, *, model=None, secret_provider=None: _InferenceErrorProvider(504),
    )
    r = await organize_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    vol = r.json()["volume_id"]
    auth = await seed_principal()
    resp = await organize_client.post(
        "/api/v1/organize/suggest", json={"volume_id": vol, "path": "/mnt/pool"}, headers=auth
    )
    assert resp.status_code == 504, resp.text
    assert resp.json()["detail"] == "inference unavailable"


async def test_suggest_empty_folder_never_calls_model(
    organize_client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """EC-organize-ai-1: an empty folder → 200, considered==0, items==[], provider never called.

    The service short-circuits before any model call when no catalogue entries fall under the root,
    so an Organize suggestion over an empty sub-folder costs nothing and proposes nothing.
    """
    provider = _NeverCalledProvider()
    monkeypatch.setattr(
        "fathom.api.routers.organize.build_inference_provider",
        lambda _s, *, model=None, secret_provider=None: provider,
    )
    r = await organize_client.post(
        "/api/v1/agents/ingest", json=batch(), headers=FINGERPRINT_HEADER
    )
    vol = r.json()["volume_id"]
    auth = await seed_principal()
    # A real, in-volume sub-folder that holds no catalogued files (seeded files live under movies/).
    resp = await organize_client.post(
        "/api/v1/organize/suggest",
        json={"volume_id": vol, "path": "/mnt/pool/empty-subdir"},
        headers=auth,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["considered"] == 0
    assert body["items"] == []
    assert provider.calls == 0  # the model was never asked


@pytest.mark.parametrize(
    "bad_body",
    [
        {"volume_id": 0, "path": "/mnt/pool"},  # volume_id ge=1
        {"volume_id": 1, "path": ""},  # path min_length=1
        {"volume_id": 1, "path": "/mnt/pool", "max_files": 0},  # max_files ge=1
        {"volume_id": 1, "path": "/mnt/pool", "max_files": 201},  # max_files le=200
    ],
)
async def test_suggest_param_validation_422(
    organize_client: httpx.AsyncClient, bad_body: dict[str, object]
) -> None:
    """EC-organize-ai-14: boundary validation rejects out-of-range params with 422 (auth valid)."""
    auth = await seed_principal()
    resp = await organize_client.post("/api/v1/organize/suggest", json=bad_body, headers=auth)
    assert resp.status_code == 422, resp.text


@pytest.mark.parametrize(
    "bad_params",
    [
        {"volume_id": 0, "path": "/mnt/pool"},  # volume_id ge=1
        {"volume_id": 1, "path": ""},  # path min_length=1
        {"volume_id": 1, "path": "/mnt/pool", "since_hours": 0},  # since_hours ge=1
        {"volume_id": 1, "path": "/mnt/pool", "since_hours": 721},  # since_hours le=720
    ],
)
async def test_activity_param_validation_422(
    organize_client: httpx.AsyncClient, bad_params: dict[str, object]
) -> None:
    """EC-organize-ai-14: the activity query params are bounded (since_hours 1..720) → 422."""
    auth = await seed_principal()
    resp = await organize_client.get("/api/v1/organize/activity", params=bad_params, headers=auth)
    assert resp.status_code == 422, resp.text


async def test_activity_capped_at_scan_limit(organize_client: httpx.AsyncClient) -> None:
    """EC-organize-ai-19: at/above the scan limit (500) the count is capped (a lower bound).

    With 500 matching change rows in the window, ``get_changes`` returns exactly the limit, so the
    route flags ``capped=True`` — the UI must show the counts as "at least", not exact.
    """
    rows = [(f"/mnt/pool/movies/f{i}.bin", "create") for i in range(500)]
    vol = await _seed_volume_with_changes(rows)
    auth = await seed_principal()
    resp = await organize_client.get(
        "/api/v1/organize/activity",
        params={"volume_id": vol, "path": "/mnt/pool/movies"},
        headers=auth,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["capped"] is True
    assert body["created"] == 500  # the scan ceiling; real churn may be higher
