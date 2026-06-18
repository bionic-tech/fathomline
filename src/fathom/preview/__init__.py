"""Preview subsystem — gVisor-sandboxed derived-artifact preview (ADR-014).

The one content path in Fathom (file-mgmt §intro): an untrusted file's raw bytes are turned into
**safe derived artifacts only** (thumbnail / page-raster + text snippet / structured highlight)
inside an egress-less, ephemeral, non-root ``runsc`` (gVisor) sandbox, never returning the raw
original (ADR-014, sec-arch §6). The raw byte stream reaches the worker via a **signed
single-file pull** over the agent-initiated mTLS channel (owner ruling; no new inbound port, no
broad mount), reusing the Ed25519 signing + single-use nonce primitives. Results live in a
bounded-LRU, encrypted-at-rest, 30-min-TTL cache holding no raw bytes (STRIDE I-8); the
``preview_cache_meta`` table holds metadata only. The route is RBAC role+scope gated and audited.
"""

from fathom.preview.cache import EncryptedLruCache, derive_cache_key
from fathom.preview.grant import (
    FileGrant,
    GrantReplayError,
    GrantSigner,
    GrantVerificationError,
    GrantVerifier,
    SignedFileGrant,
    verify_grant,
)
from fathom.preview.sandbox import RunscSandboxDriver, SandboxDriver
from fathom.preview.service import FileFetcher, PreviewService, ResolvedEntry
from fathom.preview.types import (
    PreviewArtifact,
    PreviewError,
    PreviewRequest,
    PreviewResult,
    ResourceCaps,
    SupportedType,
    detect_type,
)

__all__ = [
    "EncryptedLruCache",
    "FileFetcher",
    "FileGrant",
    "GrantReplayError",
    "GrantSigner",
    "GrantVerificationError",
    "GrantVerifier",
    "PreviewArtifact",
    "PreviewError",
    "PreviewRequest",
    "PreviewResult",
    "PreviewService",
    "ResolvedEntry",
    "ResourceCaps",
    "RunscSandboxDriver",
    "SandboxDriver",
    "SignedFileGrant",
    "SupportedType",
    "derive_cache_key",
    "detect_type",
    "verify_grant",
]
