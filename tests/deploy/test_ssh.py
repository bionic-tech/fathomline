"""Unit tests for the sudo-wrapping helper (regression guard for the live-smoke finding)."""

from __future__ import annotations

from fathom.core.deploy.ssh import wrap_sudo


def test_wrap_sudo_passwordless_uses_bash_c() -> None:
    cmd, stdin = wrap_sudo("cd /opt/x && docker compose up -d agent", password=None)
    # Compound command must run via a shell, else `sudo cd` fails (cd is a builtin).
    assert cmd.startswith("sudo -n bash -c ")
    assert "cd /opt/x && docker compose up -d agent" in cmd
    assert stdin is None


def test_wrap_sudo_with_password_feeds_stdin() -> None:
    cmd, stdin = wrap_sudo("whoami", password="hunter2")
    assert cmd.startswith("sudo -S -p '' bash -c ")
    assert stdin == "hunter2\n"


def test_wrap_sudo_quotes_the_command() -> None:
    # A command with quotes/specials is shell-quoted as a single argument to bash -c.
    cmd, _ = wrap_sudo("echo 'a b'; rm -rf nope", password=None)
    assert "bash -c " in cmd
    # The whole command is one quoted token — the trailing `; rm` is inside the quote, not a new
    # shell statement at the sudo level.
    assert cmd.count("bash -c ") == 1
