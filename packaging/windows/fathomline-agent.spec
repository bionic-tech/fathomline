# PyInstaller spec — frozen Windows executable for the Fathomline native agent (ADR-027, W1).
#
# Engine codename is "fathom" (the import package); the product/exe is "Fathomline".
# This freezes the `python -m fathom.agent` entry point into a single-file console exe named
# `fathomline-agent.exe` that the Windows enrolment bundle (fathom/core/deploy/winbundle.py)
# launches in place of `py -3 -m fathom.agent` — see winbundle._render_run_scan(), which already
# prefers a bundled `fathomline-agent.exe` and falls back to `py -3 -m fathom.agent`.
#
# IMPORTANT: this is offline-authored scaffolding. A real .exe can only be produced/validated on a
# Windows build host (or a CI `windows-latest` runner) — see README.md. Do not expect to run this
# on Linux. The constants below are the contract; the actual freeze happens in CI later.
#
# How the agent is invoked once frozen (grounded in src/fathom/agent/__main__.py):
#   * `fathomline-agent.exe scan`   → one scan→stage→push pass (the W1 default; argv[1] == "scan").
#   * `fathomline-agent.exe listen` → the ADR-025 signed-job listener (NOT shipped/used by W1, but
#     the same module entry handles it, so freezing the whole `fathom.agent` package keeps parity).
#   Wiring is read from the environment (FATHOM_AGENT_CONFIG / FATHOM_AGENT_STAGING /
#   FATHOM_AGENT_OPERATOR / FATHOM_AGENT_MODE), never argv — set by winbundle's run-scan.ps1.

# PyInstaller injects `Analysis`, `PYZ`, `EXE` etc. into this file's namespace at build time, so
# they are intentionally undefined when read as a plain Python file. This is the standard spec form.

block_cipher = None  # No bytecode encryption; the exe carries no secrets (creds are by-reference).

# --- Entry point -------------------------------------------------------------------------------
# PyInstaller cannot freeze a `-m package` invocation directly; it needs a concrete script. The
# package's runtime entry is `src/fathom/agent/__main__.py` (its `if __name__ == "__main__"` calls
# `main()` and exits with its return code), so we point Analysis at that file. argv is preserved,
# so `fathomline-agent.exe scan` lands in __main__.main() exactly as `python -m fathom.agent scan`.
ENTRY_SCRIPT = "../../src/fathom/agent/__main__.py"

# --- Bundled data files (datas) ----------------------------------------------------------------
# The staging store loads its schema as a *package resource*, not Python:
#     resources.files("fathom.agent.staging").joinpath("schema.sql").read_text("utf-8")
#       — src/fathom/agent/staging/store.py
# PyInstaller's module graph only follows imports, so a .sql data file is NOT picked up
# automatically. Without this entry the first scan crashes when StagingStore tries to read the
# schema. The dest must mirror the package path so importlib.resources finds it inside the freeze.
datas = [
    ("../../src/fathom/agent/staging/schema.sql", "fathom/agent/staging"),
]

# --- Hidden imports ----------------------------------------------------------------------------
# PyInstaller's static analysis misses imports it can't see by reading source: lazy/deferred
# imports done inside functions, native extensions loaded via C, and pydantic v2's compiled core.
# Each entry below is justified against the actual agent code.
hiddenimports = [
    # --- pydantic v2 -----------------------------------------------------------------------
    # The agent config (src/fathom/agent/config.py) and every model are pydantic v2. v2's
    # validation core is the compiled Rust extension `pydantic_core` plus a vendored
    # `typing_extensions`. PyInstaller's bundled hook usually catches these, but they are pinned
    # explicitly so a hook regression cannot silently drop the validator core (a config that
    # "validates" with no core would be a fail-open footgun, which AgentConfig is built to avoid).
    "pydantic",
    "pydantic_core",
    "pydantic.deprecated.decorator",
    # pydantic-settings (a project dep) is imported by some settings models; harmless to pin.
    "pydantic_settings",

    # --- blake3 (native extension) ---------------------------------------------------------
    # Content hashing (src/fathom/agent/reader/hasher.py: `import blake3`) is a compiled C/Rust
    # extension. PyInstaller bundles the .pyd, but the top-level import is pinned so the hasher
    # (used on a full walk) is never dropped. W1 is metadata-only, but the frozen exe is the same
    # one used for later full-bit (W2), so blake3 must be present.
    "blake3",

    # --- SQLAlchemy + async SQLite driver --------------------------------------------------
    # Staging uses SQLAlchemy async (src/fathom/agent/staging/store.py and runner.py). SQLAlchemy
    # selects its DBAPI dialect dynamically by URL (`sqlite+aiosqlite://...`), so the dialect and
    # the aiosqlite driver are imported via strings PyInstaller can't follow statically. Pin the
    # async sqlite dialect and the driver, plus the std-lib `sqlite3` it wraps (the actual DBAPI).
    "sqlalchemy",
    "sqlalchemy.dialects.sqlite",
    "sqlalchemy.dialects.sqlite.aiosqlite",
    "aiosqlite",
    "sqlite3",

    # --- PyYAML ----------------------------------------------------------------------------
    # The config loader (src/fathom/agent/loader.py: `import yaml`; `yaml.safe_load`) parses the
    # agent.config.yaml winbundle writes. PyYAML's pure-Python path is enough; the optional libyaml
    # C extension (`_yaml`) is pinned too so that if it happens to be installed on the build host
    # the C SafeLoader path still resolves inside the freeze rather than half-bundling.
    "yaml",
    "_yaml",

    # --- mTLS push transport ---------------------------------------------------------------
    # The push client (src/fathom/agent/transport/push.py) dials core over CA-pinned mTLS via httpx
    # on top of std-lib `ssl`. httpx's HTTP/2 and SOCKS extras and `ssl` can be missed; pin the ones
    # the transport actually needs. (We do NOT pin h2 unless the transport negotiates HTTP/2; httpx
    # works over HTTP/1.1 without it, so it is intentionally omitted to keep the exe lean.)
    "ssl",
    "certifi",

    # --- cryptography (Ed25519 / cert handling) --------------------------------------------
    # cryptography is used for cert/key handling and (listen mode) Ed25519 job verification. Its
    # backend is a native extension loaded through bindings PyInstaller's hook normally covers; the
    # top-level package is pinned as a guard. (Listen mode is not a W1 deliverable, but the entry
    # module imports the actor lazily, so this only matters if `listen` is ever invoked.)
    "cryptography",
]

# --- Optional / deliberately-excluded modules --------------------------------------------------
# Remote SMB/SFTP backends (asyncssh, smbprotocol/smbclient) are lazy-imported INSIDE the backend
# modules (src/fathom/backends/sftp.py, smb.py) and are only reached for `remote_targets`. A native
# Windows host scans LOCAL drives, so the default Windows bundle has no remote target. We do not pin
# them as hiddenimports: if PyInstaller's graph doesn't see the deferred import (it usually won't),
# they are simply absent and a remote-target scan would error at import — acceptable for W1 (the
# Windows agent scans local NTFS volumes; remote shares are still covered by a POSIX agent). Add
# asyncssh / smbclient here if a Windows remote-target build is ever needed.
excludes = [
    # The agent never renders the web UI or runs the API server; keep them out of the agent exe so
    # it stays small and its attack surface narrow. These are server-side only.
    "fathom.web",
    "uvicorn",
    "fastapi",
    # Preview-sandbox decode libs (Pillow/Pygments) are sandbox-image only (ADR-014); never the agent.
    "PIL",
    "pygments",
    # Postgres driver is core/server-side; the agent's only DB is the local SQLite staging file.
    "asyncpg",
]

a = Analysis(
    [ENTRY_SCRIPT],
    pathex=["../../src"],  # so `import fathom...` resolves against the src layout at build time.
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# One-file console exe. Console (not windowed) because the agent is a scheduled, non-interactive
# scan that logs to stdout/stderr — the Scheduled Task captures the stream and the process exit
# code (run-scan.ps1 does `exit $LASTEXITCODE`, and main() returns 1 on failed scopes / 2 on a
# config error). A windowed build would suppress that output and break the supervisor signal.
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="fathomline-agent",   # → dist/fathomline-agent.exe (what winbundle's launcher expects).
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                 # UPX off: AV engines flag UPX-packed exes; not worth the false-positive risk.
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch="x86_64",      # ADR-027 support matrix: x64 only (no 32-bit, no ARM64 for v1).
    codesign_identity=None,    # Code signing is a packaging-phase / MSI concern (ADR-027 deferred items).
    entitlements_file=None,
)
