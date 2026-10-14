"""Scan built wheel/sdist contents before publishing.

Rules:
- every URL host must be in ALLOWED_HOSTS;
- no private or link-local IPv4 addresses;
- no private keys or credential-looking tokens;
- optional extra words from LEAP_OAUTH_SDK_DENYLIST (comma separated, never committed).
"""

from __future__ import annotations

import os
import re
import sys
import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

ALLOWED_HOSTS = {
    "auth.example.com",
    "evil.example.com",
    "example.com",
    "github.com",
    "127.0.0.1",
    "localhost",
}
URL = re.compile(r"https?://([A-Za-z0-9.\-]+)(?::\d+)?")
PRIVATE_IP = re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01])|169\.254)(?:\.\d{1,3}){2,3}\b")
SECRET = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bskt_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{16,}"
    r"|\bpmt_ai_[A-Za-z0-9]|\bbrt1\.[A-Za-z0-9_-]{16,}|\beyJ[A-Za-z0-9_-]{20,}\.eyJ"
)


def members(path: Path) -> Iterator[tuple[str, str]]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                yield name, archive.read(name).decode("utf-8", "replace")
    else:
        with tarfile.open(path) as archive:
            for info in archive.getmembers():
                handle = archive.extractfile(info) if info.isfile() else None
                if handle is not None:
                    yield info.name, handle.read().decode("utf-8", "replace")


def main() -> int:
    artifacts = sorted(Path("dist").glob("*.whl")) + sorted(Path("dist").glob("*.tar.gz"))
    if not artifacts:
        print("no artifacts in dist/; run `uv build` first")
        return 1
    denylist = [
        word.strip().lower()
        for word in os.environ.get("LEAP_OAUTH_SDK_DENYLIST", "").split(",")
        if word.strip()
    ]
    problems: list[str] = []
    for artifact in artifacts:
        for name, text in members(artifact):
            lowered = text.lower()
            for host in URL.findall(text):
                if host.lower() not in ALLOWED_HOSTS:
                    problems.append(f"{artifact.name}:{name}: URL host not allowed: {host}")
            if PRIVATE_IP.search(text):
                problems.append(f"{artifact.name}:{name}: private IP address")
            if SECRET.search(text):
                problems.append(f"{artifact.name}:{name}: credential-like content")
            for word in denylist:
                if word in lowered or word in name.lower():
                    problems.append(f"{artifact.name}:{name}: denylisted word #{denylist.index(word)}")
    for problem in problems:
        print(problem)
    print(f"scanned {len(artifacts)} artifact(s): {'FAILED' if problems else 'clean'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
