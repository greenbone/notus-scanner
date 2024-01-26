# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module for parsing and comparing Slackware packages
"""

import logging
import re
from dataclasses import dataclass

from packaging.version import parse

from .package import Package, PackageComparison

_slack_compile = re.compile(r"(..*)-(..*)-(..*)-(\d)(?:_slack(..*))?")
_slack_compile_version = re.compile(r"(..*)-(..*)-(\d)(?:_slack(..*))?")


logger = logging.getLogger(__name__)


@dataclass
class SlackPackage(Package):
    """Represents a Slackware based package"""

    build: str
    target: str
    version: str
    arch: str

    __hash__ = Package.__hash__

    def compare(self, other: "SlackPackage") -> PackageComparison:
        if self.name != other.name:
            return PackageComparison.NOT_COMPARABLE

        if self.arch != other.arch:
            return PackageComparison.NOT_COMPARABLE

        if self.full_version == other.full_version:
            return PackageComparison.EQUAL

        comp = self.version_compare(self.version, other.version)
        if comp != PackageComparison.EQUAL:
            return comp

        a_target = parse(self.target)
        b_target = parse(other.target)

        if a_target and b_target and a_target != b_target:
            return (
                PackageComparison.A_NEWER
                if a_target > b_target
                else PackageComparison.B_NEWER
            )
        comp = self.version_compare(self.target, other.target)
        if comp != PackageComparison.EQUAL:
            return comp

        return self.version_compare(self.build, other.build)

    @staticmethod
    def from_full_name(full_name: str):
        if not full_name:
            return None

        full_name = full_name.strip()
        match = _slack_compile.match(full_name)
        if match:
            name, version, arch, build, target = match.groups()
        else:
            logger.warning(
                "The slack package %s could not be parsed", full_name
            )
            return None

        full_version = f"{version}-{arch}-{build}"

        if target:
            full_version = f"{full_version}_slack{target}"

        return SlackPackage(
            name=name,
            arch=arch,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
            build=build,
            target=target or "",
            version=version,
        )

    @staticmethod
    def from_name_and_full_version(name: str, full_version: str):
        if not name or not full_version:
            return None
        name = name.strip()
        full_version = full_version.strip()
        match = _slack_compile_version.match(full_version)
        if match:
            version, arch, build, target = match.groups()
        else:
            logger.warning(
                "The slack package %s could not be parsed",
                f"{name}-{full_version}",
            )
            return None

        return SlackPackage(
            name=name,
            arch=arch,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
            build=build,
            target=target or "",
            version=version,
        )
