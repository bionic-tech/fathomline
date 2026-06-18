"""Server-side risk classifier tests — must match the UI classifier (riskClass.test.ts)."""

from __future__ import annotations

import pytest

from fathom.core.riskclass import CONFIG, OS, SERVICES, USER, classify_path, classify_paths


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        # OS (red)
        ("/etc/passwd", OS),
        ("/usr/bin/python", OS),
        ("/scan/root/boot/vmlinuz", OS),  # /scan alias stripped; "boot" is strong-OS
        ("/mnt/c/Windows/System32/cmd.exe", OS),
        ("/etc/nginx/nginx.conf", OS),  # OS outranks a config file under an OS path
        # services (orange)
        ("/mnt/docker_data/overlay2/abc/diff/x", SERVICES),
        ("/scan/docker_images/overlay2/layer", SERVICES),
        ("/var/lib/docker/volumes/db/_data/file", SERVICES),
        ("/mnt/pgdata/base/123", SERVICES),
        # config (yellow)
        ("/mnt/apps/myapp/docker-compose.yml", CONFIG),
        ("/mnt/apps/myapp/.env", CONFIG),
        ("/mnt/apps/nginx.conf", CONFIG),
        # user (none)
        ("/scan/tank/Media/TV/show.mkv", USER),
        ("/scan/nextcloud/photos/2024/img.jpg", USER),
    ],
)
def test_classify_path(path: str, expected: str) -> None:
    assert classify_path(path) == expected


def test_classify_paths_counts() -> None:
    counts = classify_paths(
        ["/etc/x", "/mnt/docker_data/y", "/home/u/a.txt", "/home/u/compose.yaml"]
    )
    assert counts[OS] == 1
    assert counts[SERVICES] == 1
    assert counts[CONFIG] == 1
    assert counts[USER] == 1
