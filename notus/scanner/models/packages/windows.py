# SPDX-FileCopyrightText: 2021-2025 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module for parsing and comparing Windows builds
"""

import logging
from dataclasses import dataclass

from .package import Package, PackageComparison

logger = logging.getLogger(__name__)


@dataclass
class WindowsPackage(Package):
    """Represents a Windows based package"""

    prefix: str
    build: str

    __hash__ = Package.__hash__

    def compare(self, other: "WindowsPackage") -> PackageComparison:
        if self.name != other.name or self.prefix != other.prefix:
            return PackageComparison.NOT_COMPARABLE

        return self.version_compare(self.build, other.build)

    @staticmethod
    def from_full_name(full_name: str):
        if not full_name:
            return None

        full_name = full_name.strip()
        parts = full_name.split(";", 1)
        if len(parts) != 2:
            return None
        name = parts[0]
        full_version = parts[1]
        parts = full_version.rsplit(".", 1)
        if len(parts) != 2:
            return None

        return WindowsPackage(
            full_name=full_name,
            name=name,
            full_version=full_version,
            prefix=parts[0],
            build=parts[1],
        )

    @staticmethod
    def from_name_and_full_version(name: str, full_version: str):
        if not name or not full_version:
            return None

        name = name.strip()
        full_version = full_version.strip()

        full_name = f"{name};{full_version}"

        parts = full_version.rsplit(".", 1)
        if len(parts) != 2:
            return None

        return WindowsPackage(
            full_name=full_name,
            name=name,
            full_version=full_version,
            prefix=parts[0],
            build=parts[1],
        )
