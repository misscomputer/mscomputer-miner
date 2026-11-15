# Copyright (c) 2026 Ms. Computer. All rights reserved.
# SPDX-License-Identifier: LicenseRef-MsComputer-Miner
"""The production installer must install the runtime pins the sandbox-host lab proves."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _pins(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    return dict(re.findall(r"^readonly (?:MCSBX_)?([A-Z0-9_]+)=(\S+)$", text, flags=re.M))


def test_installer_runtime_pins_match_the_lab_provisioner() -> None:
    lab = _pins(ROOT / "scripts/sandbox-host/lib.sh")
    installer = _pins(ROOT / "scripts/miner-install/install.sh")
    for name in (
        "RUNSC_RELEASE",
        "RUNSC_ARCHIVE_SHA256",
        "DOCKER_VERSION",
        "CONTAINERD_VERSION",
        "CONTAINERD_ARCHIVE_SHA256",
    ):
        assert installer[name] == lab[name], name
    assert installer["SELFTEST_IMAGE"] == lab["IMAGE"]


def test_installer_python_lock_pins_the_direct_dependencies_with_hashes() -> None:

    lock = (ROOT / "scripts/miner-install/python-requirements.lock").read_text(encoding="utf-8")
    entries = re.findall(
        r"^([A-Za-z0-9_.-]+==\S+)((?: \\\n    --hash=sha256:[0-9a-f]{64})+)", lock, flags=re.M
    )
    pinned = {name.lower() for name, _ in entries}
    assert len(entries) == len(re.findall(r"^[A-Za-z0-9_.-]+==", lock, flags=re.M))
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    for requirement in project["project"]["dependencies"] + project["build-system"]["requires"]:
        assert requirement.lower() in pinned, requirement
