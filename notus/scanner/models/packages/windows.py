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

    __hash__ = Package.__hash__

    def compare(self, other: "WindowsPackage") -> PackageComparison:
        if self.name != other.name:
            return PackageComparison.NOT_COMPARABLE

        return self.version_compare(self.full_version, other.full_version)

    @staticmethod
    def from_full_name(full_name: str):
        if not full_name:
            return None

        full_name = full_name.strip()
        parts = full_name.rsplit(".", 1)
        if len(parts) != 2:
            return None

        return WindowsPackage(
            full_name=full_name, name=parts[0], full_version=parts[1]
        )

    @staticmethod
    def from_name_and_full_version(name: str, full_version: str):
        if not name or not full_version:
            return None

        build = name.strip()
        revision = full_version.strip()

        full_name = f"{build}.{revision}"

        return WindowsPackage(
            full_name=full_name, name=build, full_version=revision
        )
