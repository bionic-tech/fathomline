# ADR-039 — Notification outbound channels: Email + Chat (Discord/Slack/Telegram)

**Status:** Accepted  **Date:** 2026-06-19  **Deciders:** project owner

## Context

The Notification Center (ADR-031) gives every event an in-app home: producers call
`notifications.emit`, the bell shows it scope-filtered. But the owner's design interview was explicit
that the bell is not enough — an operator who is not looking at the UI still needs to hear *"Volume X
hit 90%"*, *"a scan failed"*, *"you'll be full in 9 days"*. The decisions taken: **operator-set
global** channels (not per-user), **Email + Chat (Discord/Slack/Telegram)**, **per-category outbound
toggles**, and **threshold alerts** — keep v1 simple (one Email channel + one Chat channel).

This lands after the runtime settings store (ADR-038), which changes the natural home for channel
configuration: channels are *settings*, so they can be configured **in-app, live, with their secrets
encrypted at rest** instead of demanding env edits + a restart.

## Decision

**Channels are configuration, dispatch is a fail-soft fan-out layer over `emit`.**

**Config = settings (ADR-038).** A `notify_*` block on `Settings`: the policy
(`notify_outbound_categories`, `notify_min_severity`), one Email/SMTP channel
(`notify_email_*`), and one Chat channel (`notify_chat_kind` ∈ discord|slack|telegram +
`notify_chat_webhook_ref`/`notify_chat_telegram_chat_id`). All are in the settings-store allow-list,
so they are editable live in the Settings UI. The SMTP password and the chat webhook URL / bot token
are **secrets by reference** (ADR-010): the `*_ref` setting names a value stored as an encrypted
named secret (ADR-038), resolved through the same `build_secret_provider` chain as the LLM keys — so
an operator can stand a channel up entirely in the browser, secret included, without touching the
host.

**Dispatch (`core/notify`).** Everything still lands in the bell; `dispatch_outbound` is the *extra*
fan-out for notes that clear **both** the category toggle and the minimum-severity threshold. It is
**best-effort and fail-soft**: each channel send is wrapped so an error/timeout is logged and
skipped — the bell row is the source of truth, an outbound failure never rolls it back or breaks the
producer. The I/O is an injectable `NotifyTransport` (httpx for chat webhooks; stdlib `smtplib` in a
worker thread for email — no new async-SMTP dependency), so tests drive dispatch without a network.
`emit_and_dispatch` is the one call a producer (e.g. the proactive watcher, ADR-040) makes to do
both; existing `emit` callers stay in-app-only.

**Telegram** is the one shape difference: its `*_ref` resolves to a **bot token**, and the API URL
(`/bot<token>/sendMessage` with `chat_id`) is built server-side; Discord/Slack resolve to a full
webhook URL posted directly.

**Surface.** `POST /api/v1/notifications/test` (admin / `MANAGE_SETTINGS`) sends a connectivity
test to each *enabled* channel and reports per-channel `ok`+`detail` — deliberately **not** gated on
`notifications_enabled` so an admin can verify config before flipping the master gate. The Settings
page renders the `notify_*` settings (grouped, secrets masked) plus a "Send test" button; the bell
in the app shell shows the in-app channel.

## Consequences

- **Stand-up is in-app and live.** Enable a channel, paste the webhook/SMTP secret (encrypted),
  click "Send test", then flip `notifications_enabled` — no restart, no env edit.
- **The bell is never lost to a channel failure.** Dispatch is strictly additive and swallows
  channel errors; the in-app record always succeeds first.
- **v1 is one Email + one Chat**, by design. Multiple/again-per-host channels and richer routing are
  a later wave; the policy (`category` + `severity`) is the deliberate simple knob now.
- **Secrets stay by-reference (ADR-010/038).** No webhook URL or SMTP password is stored in plain
  settings or returned unmasked except through the step-up-gated reveal.
- **No new tables / migration.** Channels are settings; the bell store (ADR-031) is unchanged.
- **Reuses, not forks, the trust model.** Admin-only config, encrypted secrets, the same secret
  provider chain as the LLM providers.
