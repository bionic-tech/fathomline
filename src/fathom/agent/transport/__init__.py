"""Agent transport — mTLS push to the core ingest API (ADR-002).

Stage 2 ships the agent-push client: a CA-pinned mTLS HTTP client (AR-0010), a resumable
drain of the local staging queue, and reconnect backoff with jitter (AR-0024). SSH-exec is
a later transport behind the same boundary (ADR-002).
"""

from fathom.agent.transport.push import PushClient, RetryPolicy, mtls_client

__all__ = ["PushClient", "RetryPolicy", "mtls_client"]
