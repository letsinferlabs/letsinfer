#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Resolve the independently versioned macOS release identity."""

from __future__ import annotations

import argparse
import json
import pathlib
import plistlib
import re
from typing import Any


VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?$")
BUILD_RE = re.compile(r"^[1-9][0-9]*$")


class MacOSReleaseError(RuntimeError):
    """The macOS version/build contract is inconsistent."""


def _one(pattern: str, value: str, field: str) -> str:
    matches = re.findall(pattern, value, flags=re.MULTILINE)
    if len(matches) != 1:
        raise MacOSReleaseError(f"{field} must appear exactly once in project.yml")
    return matches[0]


def release_metadata(root: pathlib.Path | None = None) -> dict[str, Any]:
    root = (root or pathlib.Path(__file__).resolve().parent).resolve(strict=True)
    project = (root / "project.yml").read_text(encoding="utf-8")
    generated = (root / "LetsInfer.xcodeproj/project.pbxproj").read_text(
        encoding="utf-8"
    )
    with (root / "LetsInfer/Info.plist").open("rb") as handle:
        info = plistlib.load(handle)

    version = _one(
        r'^\s+MARKETING_VERSION:\s*"([^"]+)"\s*$', project, "MARKETING_VERSION"
    )
    build = _one(
        r'^\s+CURRENT_PROJECT_VERSION:\s*"([^"]+)"\s*$',
        project,
        "CURRENT_PROJECT_VERSION",
    )
    if VERSION_RE.fullmatch(version) is None:
        raise MacOSReleaseError("MARKETING_VERSION is not a release version")
    if BUILD_RE.fullmatch(build) is None:
        raise MacOSReleaseError("CURRENT_PROJECT_VERSION is not a positive integer")

    generated_versions = set(re.findall(r"MARKETING_VERSION = ([^;]+);", generated))
    generated_builds = set(
        re.findall(r"CURRENT_PROJECT_VERSION = ([^;]+);", generated)
    )
    if generated_versions != {version} or generated_builds != {build}:
        raise MacOSReleaseError("generated Xcode project version differs from project.yml")
    if info.get("CFBundleShortVersionString") != "$(MARKETING_VERSION)":
        raise MacOSReleaseError("Info.plist must derive the marketing version from Xcode")
    if info.get("CFBundleVersion") != "$(CURRENT_PROJECT_VERSION)":
        raise MacOSReleaseError("Info.plist must derive the build number from Xcode")
    if "LetsInferRelease" in info:
        raise MacOSReleaseError("macOS bundle metadata must not embed the core release")

    return {
        "artifact": f"LetsInfer-{version}-build.{build}-macOS.zip",
        "build": build,
        "prerelease": "-rc." in version,
        "tag": f"macos-v{version}-build.{build}",
        "version": version,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-output", type=pathlib.Path)
    arguments = parser.parse_args()
    metadata = release_metadata()
    if arguments.github_output is None:
        print(json.dumps(metadata, sort_keys=True, separators=(",", ":")))
    else:
        with arguments.github_output.open("a", encoding="utf-8") as output:
            for key in ("version", "build", "tag", "artifact", "prerelease"):
                value = metadata[key]
                if isinstance(value, bool):
                    value = str(value).lower()
                output.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
