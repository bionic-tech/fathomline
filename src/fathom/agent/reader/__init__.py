"""The reader: metadata/full-bit collection with no write capability (ADD 02).

Stage 1 ships the metadata path — the throttled scan orchestrator (:mod:`walker`) and the
adaptive load supervisor (:mod:`supervisor`). The hasher (progressive BLAKE3) and the
full-bit path are later stages; the actor/write path lives in a different package, under a
different OS user, by design.
"""

from fathom.agent.reader.feed import (
    ChangeDelta,
    ChangeEvent,
    ChangeFeed,
    RestatFeed,
    ZfsDiffFeed,
    collect_delta,
)
from fathom.agent.reader.fullbit import (
    FullBitBlocked,
    FullBitResult,
    FullBitScanner,
)
from fathom.agent.reader.incremental import IncrementalResult, IncrementalScanner
from fathom.agent.reader.supervisor import LoadSupervisor
from fathom.agent.reader.walker import (
    AcknowledgementRequired,
    MetadataScanner,
    ScanResult,
    WarningAck,
)

__all__ = [
    "AcknowledgementRequired",
    "ChangeDelta",
    "ChangeEvent",
    "ChangeFeed",
    "FullBitBlocked",
    "FullBitResult",
    "FullBitScanner",
    "IncrementalResult",
    "IncrementalScanner",
    "LoadSupervisor",
    "MetadataScanner",
    "RestatFeed",
    "ScanResult",
    "WarningAck",
    "ZfsDiffFeed",
    "collect_delta",
]
