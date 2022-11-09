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
Module for parsing and comparing Debian packages (.deb)
"""

import logging
import re
from dataclasses import dataclass

from .package import Package, PackageComparison

_deb_compile = re.compile(r"(.*)-(?:(\d*):)?(\d.*)-(.*)")
_deb_compile_wo_revision = re.compile(r"(.*)-(?:(\d*):)?(\d.*)")
_deb_compile_version = re.compile(r"(?:(\d*):)?(\d.*)-(.*)")
_deb_compile_version_wo_revision = re.compile(r"(?:(\d*):)?(\d.*)")


logger = logging.getLogger(__name__)


@dataclass
class DEBPackage(Package):
    """Represents a .deb based package"""

    upstream_version: str
    debian_revision: str
    epoch: str

    __hash__ = Package.__hash__

    def compare(self, other: "DEBPackage") -> PackageComparison:
        if self.name != other.name:
            return PackageComparison.NOT_COMPARABLE

        if self.full_version == other.full_version:
            return PackageComparison.EQUAL

        if self.epoch != other.epoch:
            return (
                PackageComparison.A_NEWER
                if self.epoch > other.epoch
                else PackageComparison.B_NEWER
            )

        comp = self.version_compare(
            self.upstream_version, other.upstream_version
        )
        if comp != PackageComparison.EQUAL:
            return comp

        return self.version_compare(self.debian_revision, other.debian_revision)

    @staticmethod
    def from_full_name(full_name: str):
        if not full_name:
            return None

        full_name = full_name.strip()

        match = _deb_compile.match(full_name)
        # Try to get data with
        if match:
            name, epoch, upstream_version, debian_revision = match.groups()
        else:
            match = _deb_compile_wo_revision.match(full_name)
            if match:
                name, epoch, upstream_version = match.groups()
                debian_revision = ""
            else:
                logger.warning(
                    "The deb package %s could not be parsed", full_name
                )
                return None

        if not epoch:
            epoch = "0"
            full_version = f"{upstream_version}"
        else:
            full_version = f"{epoch}:{upstream_version}"

        if debian_revision:
            full_version = f"{full_version}-{debian_revision}"

        return DEBPackage(
            name=name,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
            epoch=epoch,
            upstream_version=upstream_version,
            debian_revision=debian_revision,
        )

    @staticmethod
    def from_name_and_full_version(name: str, full_version: str):
        if not name or not full_version:
            return None
        name = name.strip()
        full_version = full_version.strip()
        match = _deb_compile_version.match(full_version)
        if match:
            (
                epoch,
                upstream_version,
                debian_revision,
            ) = match.groups()
        else:
            match = _deb_compile_version_wo_revision.match(full_version)
            if match:
                (
                    epoch,
                    upstream_version,
                ) = match.groups()
                debian_revision = ""
            else:
                logger.warning(
                    "The deb package %s %s could not be parsed",
                    name,
                    full_version,
                )
                return None

        if not epoch:
            epoch = "0"

        return DEBPackage(
            name=name,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
            epoch=epoch,
            upstream_version=upstream_version,
            debian_revision=debian_revision,
        )
