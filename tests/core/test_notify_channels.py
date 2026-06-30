"""Outbound notification channel tests (ADR-039) — policy, dispatch, fail-soft, secret chain.

A fake transport records every send so dispatch is exercised without touching the network. The
security-relevant bits: the category + severity policy gates fan-out; a channel error is swallowed
(the bell row is the source of truth); secret references (SMTP password, chat webhook/bot token)
resolve through the injected provider; and ``send_test`` reports each channel's outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from fathom.core.notify import dispatch_outbound, send_test, should_dispatch
from fathom.core.notify.channels import OutboundNote
from fathom.core.settings import Settings


@dataclass
class FakeTransport:
    """Records webhook + email sends instead of performing them; can be told to fail."""

    posts: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    emails: list[dict[str, Any]] = field(default_factory=list)
    fail: bool = False

    async def post_json(self, url: str, payload: dict[str, Any], *, timeout_seconds: float) -> None:
        if self.fail:
            raise RuntimeError("boom")
        self.posts.append((url, payload))

    async def send_email(self, **kw: Any) -> None:
        if self.fail:
            raise RuntimeError("smtp down")
        self.emails.append(kw)


def _secret(mapping: dict[str, str]) -> Any:
    def provider(ref: str) -> str:
        return mapping[ref]

    return provider


def _note(category: str = "problem", severity: str = "warning") -> OutboundNote:
    return OutboundNote(
        category=category,
        severity=severity,
        title="Disk 95% full",
        body="nas-1 / tank",
        source="capacity",
    )


def test_should_dispatch_policy() -> None:
    s = Settings(
        notify_outbound_categories=("problem", "security"),
        notify_min_severity="warning",
    )
    assert should_dispatch(s, category="problem", severity="warning") is True
    assert should_dispatch(s, category="problem", severity="critical") is True
    assert should_dispatch(s, category="problem", severity="info") is False  # below threshold
    assert should_dispatch(s, category="activity", severity="critical") is False  # category off
    assert should_dispatch(s, category="problem", severity="bogus") is False  # unknown severity


async def test_dispatch_respects_master_gate() -> None:
    s = Settings(notifications_enabled=False, notify_email_enabled=True)
    tx = FakeTransport()
    assert await dispatch_outbound(s, _secret({}), _note(), transport=tx) == []


async def test_dispatch_email_and_discord() -> None:
    s = Settings(
        notifications_enabled=True,
        notify_outbound_categories=("problem",),
        notify_min_severity="warning",
        notify_email_enabled=True,
        notify_email_smtp_host="smtp.example.com",
        notify_email_from="fathom@example.com",
        notify_email_to=("ops@example.com",),
        notify_email_password_ref="SMTP_PW",
        notify_chat_enabled=True,
        notify_chat_kind="discord",
        notify_chat_webhook_ref="DISCORD_HOOK",
    )
    tx = FakeTransport()
    delivered = await dispatch_outbound(
        s,
        _secret({"SMTP_PW": "pw", "DISCORD_HOOK": "https://discord/webhook"}),
        _note(),
        transport=tx,
    )
    assert delivered == ["email", "chat:discord"]
    assert tx.emails[0]["password"] == "pw"
    assert tx.emails[0]["recipients"] == ("ops@example.com",)
    assert tx.posts[0][0] == "https://discord/webhook"
    assert "content" in tx.posts[0][1]


async def test_dispatch_telegram_builds_api_url() -> None:
    s = Settings(
        notifications_enabled=True,
        notify_outbound_categories=("problem",),
        notify_min_severity="info",
        notify_chat_enabled=True,
        notify_chat_kind="telegram",
        notify_chat_webhook_ref="BOT_TOKEN",
        notify_chat_telegram_chat_id="12345",
    )
    tx = FakeTransport()
    delivered = await dispatch_outbound(s, _secret({"BOT_TOKEN": "abc:def"}), _note(), transport=tx)
    assert delivered == ["chat:telegram"]
    url, payload = tx.posts[0]
    assert url == "https://api.telegram.org/botabc:def/sendMessage"
    assert payload["chat_id"] == "12345"


async def test_dispatch_is_fail_soft() -> None:
    s = Settings(
        notifications_enabled=True,
        notify_outbound_categories=("problem",),
        notify_min_severity="warning",
        notify_chat_enabled=True,
        notify_chat_kind="slack",
        notify_chat_webhook_ref="HOOK",
    )
    tx = FakeTransport(fail=True)
    # The transport raises, but dispatch swallows it → no channel reported delivered, no exception.
    assert (
        await dispatch_outbound(s, _secret({"HOOK": "https://slack/hook"}), _note(), transport=tx)
        == []
    )


async def test_dispatch_skips_below_threshold() -> None:
    s = Settings(
        notifications_enabled=True,
        notify_outbound_categories=("problem",),
        notify_min_severity="critical",
        notify_chat_enabled=True,
        notify_chat_kind="discord",
        notify_chat_webhook_ref="HOOK",
    )
    tx = FakeTransport()
    assert (
        await dispatch_outbound(s, _secret({"HOOK": "x"}), _note(severity="warning"), transport=tx)
        == []
    )


async def test_send_test_reports_each_channel() -> None:
    s = Settings(
        notify_email_enabled=True,
        notify_email_smtp_host="smtp.example.com",
        notify_email_from="f@example.com",
        notify_email_to=("ops@example.com",),
        notify_chat_enabled=True,
        notify_chat_kind="discord",
        notify_chat_webhook_ref="HOOK",
    )
    tx = FakeTransport()
    results = await send_test(s, _secret({"HOOK": "https://discord/h"}), transport=tx)
    by = {r.channel: r for r in results}
    assert by["email"].ok is True
    assert by["chat:discord"].ok is True


async def test_send_test_reports_misconfig() -> None:
    s = Settings(notify_email_enabled=True, notify_chat_enabled=True, notify_chat_kind="slack")
    tx = FakeTransport()
    results = await send_test(s, _secret({}), transport=tx)
    by = {r.channel: r for r in results}
    assert by["email"].ok is False and "smtp" in by["email"].detail
    assert by["chat:slack"].ok is False and "webhook" in by["chat:slack"].detail


@pytest.mark.parametrize("kind", ["discord", "slack", "telegram"])
def test_settings_accepts_each_chat_kind(kind: str) -> None:
    Settings(notify_chat_kind=kind)  # no raise — the three supported kinds


@dataclass
class TimeoutTransport:
    """A transport that always times out — records the per-send timeout it was handed, then raises.

    (channels.py forwards ``notify_send_timeout_seconds`` to the transport; the real httpx/smtplib
    transport is what enforces it and raises, so a mock simulates the timeout by raising.)
    """

    seen: list[float] = field(default_factory=list)

    async def post_json(self, url: str, payload: dict[str, Any], *, timeout_seconds: float) -> None:
        self.seen.append(timeout_seconds)
        raise TimeoutError(f"send timed out after {timeout_seconds}s")

    async def send_email(self, *, timeout_seconds: float, **kw: Any) -> None:
        self.seen.append(timeout_seconds)
        raise TimeoutError(f"send timed out after {timeout_seconds}s")


async def test_dispatch_timeout_is_fail_soft() -> None:
    # A channel that exceeds notify_send_timeout_seconds (here the transport times out) is swallowed
    # exactly like any other channel error — the bell row is the source of truth, so nothing is
    # reported delivered and no exception propagates. The configured timeout is handed through to
    # the transport. (EC-notifications-9)
    s = Settings(
        notifications_enabled=True,
        notify_outbound_categories=("problem",),
        notify_min_severity="warning",
        notify_send_timeout_seconds=0.5,
        notify_chat_enabled=True,
        notify_chat_kind="slack",
        notify_chat_webhook_ref="HOOK",
    )
    tx = TimeoutTransport()
    delivered = await dispatch_outbound(
        s, _secret({"HOOK": "https://slack/hook"}), _note(), transport=tx
    )
    assert delivered == []  # fail-soft: the timeout is swallowed
    assert tx.seen == [0.5]  # the configured per-send timeout reached the transport


async def test_send_test_reports_timeout_detail() -> None:
    # The connectivity test surfaces the timeout as ok=False with the failure detail (so an operator
    # sees WHY the channel failed), and still forwards the configured timeout. (EC-notifications-9)
    s = Settings(
        notify_send_timeout_seconds=0.5,
        notify_chat_enabled=True,
        notify_chat_kind="slack",
        notify_chat_webhook_ref="HOOK",
    )
    tx = TimeoutTransport()
    results = await send_test(s, _secret({"HOOK": "https://slack/hook"}), transport=tx)
    by = {r.channel: r for r in results}
    assert by["chat:slack"].ok is False
    assert "timed out" in by["chat:slack"].detail
    assert tx.seen == [0.5]
