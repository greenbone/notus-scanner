# Copyright (C) 2021-2022 Greenbone Networks GmbH
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
"""
Module for parsing and comparing Slackware packages
"""

import logging
import re
from dataclasses import dataclass
from packaging.version import parse

from .package import Architecture, Package, PackageComparision

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

    def _compare(self, other: "SlackPackage") -> PackageComparision:
        if self.arch != other.arch:
            return PackageComparision.NOT_COMPARABLE

        if self.full_version == other.full_version:
            return PackageComparision.EQUAL

        a_version = parse(self.version)
        b_version = parse(other.version)

        if a_version != b_version:
            return (
                PackageComparision.A_NEWER
                if a_version > b_version
                else PackageComparision.B_NEWER
            )

        a_target = parse(self.target)
        b_target = parse(other.target)

        if a_target and b_target and a_target != b_target:
            return (
                PackageComparision.A_NEWER
                if a_target > b_target
                else PackageComparision.B_NEWER
            )

        a_build = parse(self.build)
        b_build = parse(other.build)

        if a_build != b_build:
            return (
                PackageComparision.A_NEWER
                if a_build > b_build
                else PackageComparision.B_NEWER
            )

    @staticmethod
    def from_full_name(full_name: str):
        if not full_name:
            return None

        full_name = full_name.strip()
        try:
            name, version, architecture, build, target = _slack_compile.match(
                full_name
            ).groups()
        except AttributeError:
            logger.warning(
                "The slack package %s could not be parsed", full_name
            )
            return None

        try:
            arch = Architecture(architecture)
        except ValueError:
            arch = Architecture.UNKNOWN

        full_version = f"{version}-{arch.value}-{build}"

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
        try:
            version, architecture, build, target = _slack_compile_version.match(
                full_version
            ).groups()
        except AttributeError:
            logger.warning(
                "The slack package %s could not be parsed",
                f"{name}-{full_version}",
            )
            return None

        try:
            arch = Architecture(architecture)
        except ValueError:
            arch = Architecture.UNKNOWN

        return SlackPackage(
            name=name,
            arch=arch,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
            build=build,
            target=target or "",
            version=version,
        )
