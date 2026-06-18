"""E2E feature verifier — drive every Fathom feature over HTTP and assert the result tallies with
both the expected synthetic corpus (scripts/e2e/seed_e2e.py) AND a direct read of the server DB.

For each feature it records a check with: the API value, the DB value, the expected value, and a
PASS/FAIL verdict + human-readable detail. Writes a structured report to --report and a readable
log to stdout; exits non-zero if any check fails (so run_e2e.sh's auto-fix loop can react).

Read-only and destruction-free: it exercises the remediation/organize *build* paths (which persist
a plan but touch no files) and NEVER calls execute or dry-run dispatch — no data is ever deleted.

Usage:  uv run python scripts/e2e/verify.py --api URL --db PATH --expected /tmp/fathom-e2e/expected.json
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys

import httpx

USER = "admin"


class Report:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def add(self, name: str, passed: bool, *, api=None, db=None, expected=None, detail: str = "") -> None:
        self.checks.append(
            {"name": name, "passed": passed, "api": api, "db": db, "expected": expected, "detail": detail}
        )
        mark = "PASS" if passed else "FAIL"
        print(f"  [{mark}] {name}: {detail}")

    @property
    def ok(self) -> bool:
        return all(c["passed"] for c in self.checks)


def db_query(db: str, sql: str, params: tuple = ()) -> list[tuple]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30)
    try:
        con.execute("PRAGMA busy_timeout=30000")
        return list(con.execute(sql, params).fetchall())
    finally:
        con.close()


def login(api: str, password: str) -> httpx.Client:
    c = httpx.Client(base_url=api, timeout=60.0)
    r = c.post("/api/v1/auth/login", json={"username": USER, "password": password})
    if r.status_code not in (200, 204):
        raise SystemExit(f"login failed: HTTP {r.status_code} {r.text[:200]}")
    return c


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8099")
    ap.add_argument("--db", required=True)
    ap.add_argument("--expected", default="/tmp/fathom-e2e/expected.json")
    ap.add_argument("--password", default="localdev-admin-pw")
    ap.add_argument("--report", default="/tmp/fathom-e2e/verify-report.json")
    args = ap.parse_args()

    with open(args.expected) as fh:
        exp = json.load(fh)
    rep = Report()
    c = login(args.api, args.password)

    # ---- volumes (map mountpoint -> id) -------------------------------------------------------
    vols = c.get("/api/v1/volumes").json()
    vol_by_mount = {v["mountpoint"]: v for v in vols}
    db_vol_count = db_query(args.db, "SELECT count(*) FROM volume")[0][0]
    rep.add(
        "volumes/list",
        len(vols) == db_vol_count == 3,
        api=len(vols), db=db_vol_count, expected=3,
        detail=f"{len(vols)} volumes via API, {db_vol_count} in DB (expected 3)",
    )
    data_id = vol_by_mount.get("/data", {}).get("id")
    raid_id = vol_by_mount.get("/raid", {}).get("id")
    nfs = vol_by_mount.get("/nfsmnt")
    rep.add(
        "volumes/nfs-fs-type",
        bool(nfs) and nfs["fs_type"] == "nfs",
        api=nfs and nfs["fs_type"], expected="nfs",
        detail=f"/nfsmnt fs_type = {nfs and nfs['fs_type']}",
    )

    # ---- agents -------------------------------------------------------------------------------
    agents = {h["name"]: h for h in c.get("/api/v1/agents").json()}
    for name, e in exp["hosts"].items():
        h = agents.get(name, {})
        ok = h.get("volume_count") == e["volume_count"] and h.get("last_run_outcome") in ("ok", "partial")
        rep.add(
            f"agents/{name}",
            ok,
            api={"vols": h.get("volume_count"), "run": h.get("last_run_outcome")},
            expected={"vols": e["volume_count"], "run": "ok|partial"},
            detail=f"{name}: {h.get('volume_count')} vols, last run {h.get('last_run_outcome')}",
        )

    # ---- duplicates: summary + cross-host group + cross-mount alias ----------------------------
    summary = c.get("/api/v1/duplicates/summary").json()
    db_count, db_reclaim = db_query(
        args.db, "SELECT count(*), COALESCE(SUM(reclaimable_bytes),0) FROM dup_group"
    )[0]
    de = exp["duplicates"]
    rep.add(
        "duplicates/summary",
        summary["group_count"] == db_count == de["group_count"]
        and summary["total_reclaimable_bytes"] == db_reclaim == de["total_reclaimable_bytes"],
        api=summary, db={"count": db_count, "reclaimable": db_reclaim}, expected=de,
        detail=f"API groups={summary['group_count']} reclaim={summary['total_reclaimable_bytes']}; "
        f"DB groups={db_count} reclaim={db_reclaim}; expected groups={de['group_count']} "
        f"reclaim={de['total_reclaimable_bytes']}",
    )
    groups = c.get("/api/v1/duplicates").json()["items"]
    by_hash = {g["full_hash"]: g for g in groups}
    # cross-host genuine duplicate
    ch = by_hash.get(de["cross_host_group"]["full_hash"], {})
    rep.add(
        "duplicates/cross-host",
        ch.get("reclaimable_bytes") == de["cross_host_group"]["reclaimable_bytes"]
        and ch.get("member_count") == de["cross_host_group"]["members"],
        api=ch, expected=de["cross_host_group"],
        detail=f"cross-host group reclaim={ch.get('reclaimable_bytes')} members={ch.get('member_count')}",
    )
    # cross-mount alias false-positive (ADR-032): reclaimable 0, exactly one alias member
    ag = by_hash.get(de["alias_group"]["full_hash"], {})
    alias_members_api = 0
    if ag:
        detail_g = c.get(f"/api/v1/duplicates/{ag['id']}").json()
        alias_members_api = sum(1 for m in detail_g["members"] if m["is_mount_alias"])
    alias_members_db = db_query(
        args.db,
        "SELECT count(*) FROM dup_member dm JOIN dup_group dg ON dg.id=dm.group_id "
        "WHERE dg.full_hash=? AND dm.is_mount_alias=1",
        (de["alias_group"]["full_hash"],),
    )[0][0]
    rep.add(
        "duplicates/cross-mount-alias",
        ag.get("reclaimable_bytes") == 0
        and alias_members_api == alias_members_db == de["alias_group"]["alias_members"],
        api={"reclaimable": ag.get("reclaimable_bytes"), "alias_members": alias_members_api},
        db={"alias_members": alias_members_db}, expected=de["alias_group"],
        detail=f"alias group reclaim={ag.get('reclaimable_bytes')} (expect 0); "
        f"alias members API={alias_members_api} DB={alias_members_db} (expect 1)",
    )

    # ---- largest files (top-n) ----------------------------------------------------------------
    if data_id:
        topn = c.get(
            "/api/v1/top-n",
            params={"volume_id": data_id, "path": "/data/downloads", "n": 10, "by": "on_disk", "kind": "file"},
        ).json()
        api_pairs = [[i["name"], i["size_on_disk"]] for i in topn]
        rep.add(
            "largest/top-n",
            api_pairs == exp["largest_under_downloads"],
            api=api_pairs, expected=exp["largest_under_downloads"],
            detail=f"top files under /data/downloads: {[p[0] for p in api_pairs]}",
        )

    # ---- treemap (subtree sizes) --------------------------------------------------------------
    if data_id:
        tm = c.get(
            "/api/v1/treemap", params={"volume_id": data_id, "path": "/data", "depth": 1, "limit": 50}
        ).json()
        tm_by_name = {n["name"]: n["subtree_size_on_disk"] for n in tm}
        exp_tm = exp["treemap_data_children"]
        ok = all(tm_by_name.get(k) == v for k, v in exp_tm.items())
        rep.add(
            "explorer/treemap",
            ok,
            api=tm_by_name, expected=exp_tm,
            detail=f"/data children sizes: {tm_by_name}",
        )

    # ---- search -------------------------------------------------------------------------------
    sr = c.get("/api/v1/search", params={"q": "movie"}).json()
    rep.add(
        "search/movie",
        len(sr) == exp["search_movie_count"],
        api=len(sr), expected=exp["search_movie_count"],
        detail=f"search 'movie' -> {len(sr)} hits (expect {exp['search_movie_count']})",
    )

    # ---- AI organize: suggest (mock LLM) -> plan (build only; no files moved) ------------------
    org = exp["organize"]
    if data_id:
        sug = c.post(
            "/api/v1/organize/suggest",
            json={"volume_id": data_id, "path": org["root"], "max_files": 60},
        )
        if sug.status_code == 200:
            proposal = sug.json()
            moves, cat_ok = [], True
            for it in proposal["items"]:
                if it["status"] == "move":
                    moves.append({"entry_id": it["entry_id"], "dest_rel": it["proposed_relpath"]})
                    want = org["expected_moves"].get(it["current_name"])
                    if want and not it["proposed_relpath"].startswith(want + "/"):
                        cat_ok = False
            rep.add(
                "organize/suggest",
                cat_ok and len(moves) == org["plan_blast_count"],
                api={"moves": len(moves), "considered": proposal["considered"]},
                expected={"moves": org["plan_blast_count"]},
                detail=f"suggested {len(moves)} moves, by-type grouping ok={cat_ok}",
            )
            plan = c.post(
                "/api/v1/organize/plan",
                json={"volume_id": data_id, "path": org["root"], "moves": moves},
            )
            if plan.status_code in (200, 201):
                po = plan.json()
                db_plan = db_query(
                    args.db,
                    "SELECT blast_count, reclaimable_bytes FROM remediation_plan "
                    "WHERE plan_id=?",
                    (po["plan_id"],),
                )
                db_bc, db_rb = (db_plan[0] if db_plan else (None, None))
                rep.add(
                    "organize/plan-build",
                    po["blast_count"] == db_bc == org["plan_blast_count"]
                    and po["reclaimable_bytes"] == db_rb == org["plan_reclaimable_bytes"],
                    api={"blast": po["blast_count"], "bytes": po["reclaimable_bytes"]},
                    db={"blast": db_bc, "bytes": db_rb},
                    expected={"blast": org["plan_blast_count"], "bytes": org["plan_reclaimable_bytes"]},
                    detail=f"plan {po['plan_id']}: blast={po['blast_count']} bytes={po['reclaimable_bytes']} "
                    f"(DB blast={db_bc} bytes={db_rb})",
                )
            else:
                rep.add("organize/plan-build", False, detail=f"plan HTTP {plan.status_code}: {plan.text[:200]}")
        else:
            rep.add("organize/suggest", False, detail=f"suggest HTTP {sug.status_code}: {sug.text[:200]}")

    # ---- reconcile ----------------------------------------------------------------------------
    rc = exp["reconcile"]
    if data_id and raid_id:
        rr = c.post(
            "/api/v1/reconcile",
            json={
                "definitive_volume_id": data_id, "definitive_path": rc["definitive"],
                "comparison_volume_id": raid_id, "comparison_path": rc["comparison"],
            },
        )
        if rr.status_code == 200:
            counts = rr.json()["counts"]
            rep.add(
                "reconcile/mirror",
                counts.get("identical") == rc["identical"]
                and counts.get("missing_on_comparison") == rc["missing_on_comparison"],
                api=counts, expected={k: rc[k] for k in ("identical", "missing_on_comparison")},
                detail=f"reconcile counts: {counts}",
            )
        else:
            rep.add("reconcile/mirror", False, detail=f"reconcile HTTP {rr.status_code}: {rr.text[:200]}")

    # ---- remediation BUILD from the cross-host dup group (side-effect-free; no execute) --------
    if ch:
        gid = ch["id"]
        detail_g = c.get(f"/api/v1/duplicates/{gid}").json()
        keeper = detail_g.get("suggested_keeper_entry_id") or detail_g["members"][0]["entry_id"]
        pb = c.post(
            "/api/v1/remediation/plans",
            json={"group_id": gid, "keep_entry_id": keeper, "action": "quarantine"},
        )
        if pb.status_code in (200, 201):
            po = pb.json()
            rep.add(
                "remediation/build",
                po["blast_count"] == de["cross_host_group"]["members"] - 1,
                api={"blast": po["blast_count"], "status": po["status"]},
                expected={"blast": de["cross_host_group"]["members"] - 1, "status": "built"},
                detail=f"built plan {po['plan_id']} blast={po['blast_count']} (no files touched)",
            )
        else:
            rep.add("remediation/build", False, detail=f"build HTTP {pb.status_code}: {pb.text[:200]}")

    # ---- scans + changes ----------------------------------------------------------------------
    scans = c.get("/api/v1/scans").json()
    db_snaps = db_query(args.db, "SELECT count(*) FROM snapshot")[0][0]
    rep.add(
        "scans/list",
        len(scans) >= 3 and db_snaps >= 3,
        api=len(scans), db=db_snaps, expected=">=3",
        detail=f"{len(scans)} snapshots via API, {db_snaps} in DB",
    )
    if data_id:
        changes = c.get("/api/v1/changes", params={"volume_id": data_id}).json()
        rep.add(
            "changes/feed",
            len(changes) > 0,
            api=len(changes), expected=">0",
            detail=f"{len(changes)} change_log rows for /data",
        )

    # ---- audit chain continuity ---------------------------------------------------------------
    audit = c.get("/api/v1/audit").json()
    rows = db_query(args.db, "SELECT seq, prev_hash, row_hash FROM remediation_audit ORDER BY seq")
    chain_ok = True
    for i in range(1, len(rows)):
        if rows[i][1] != rows[i - 1][2]:  # prev_hash must equal prior row_hash
            chain_ok = False
            break
    rep.add(
        "audit/chain",
        len(audit["items"]) > 0 and len(rows) > 0 and chain_ok,
        api=len(audit["items"]), db=len(rows), expected="continuous chain",
        detail=f"{len(rows)} audit rows, BLAKE3 chain continuous={chain_ok}",
    )

    # ---- write report -------------------------------------------------------------------------
    passed = sum(1 for x in rep.checks if x["passed"])
    total = len(rep.checks)
    out = {"passed": passed, "total": total, "ok": rep.ok, "checks": rep.checks}
    with open(args.report, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\n==== {passed}/{total} checks passed -> {args.report} ====")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
