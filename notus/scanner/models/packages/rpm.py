# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
import re
from dataclasses import dataclass

from .package import Package, PackageComparison

_rpm_compile = re.compile(r"^(.*)-(?:(\d+):)?([^-]+)-([^-]+)\.([^-]+)$")
_rpm_compile_version = re.compile(r"^(?:(\d+):)?([^-]+)-([^-]+)\.([^-]+)$")

logger = logging.getLogger(__name__)

exceptions = [
    "_fips",
    ".ksplice",
]


@dataclass
class RPMPackage(Package):
    """Represents a RPM package"""

    epoch: int
    version: str
    release: str
    arch: str

    __hash__ = Package.__hash__

    def compare(self, other: "RPMPackage") -> PackageComparison:
        if self.name != other.name:
            return PackageComparison.NOT_COMPARABLE

        if self.arch != other.arch:
            return PackageComparison.NOT_COMPARABLE

        for e in exceptions:
            if (self.full_version.find(e) > -1) != (
                other.full_version.find(e) > -1
            ):
                return PackageComparison.NOT_COMPARABLE

        if self.full_version == other.full_version:
            return PackageComparison.EQUAL

        if self.epoch != other.epoch:
            return (
                PackageComparison.A_NEWER
                if self.epoch > other.epoch
                else PackageComparison.B_NEWER
            )

        comp = self.version_compare(self.version, other.version)
        if comp != PackageComparison.EQUAL:
            return comp

        return self.version_compare(self.release, other.release)

    @staticmethod
    def from_full_name(full_name: str):
        if not full_name:
            return None

        full_name = full_name.strip()

        match = _rpm_compile.match(full_name)
        # Check if given package string could be parsed
        if not match:
            logger.warning("The rpm package %s could not be parsed", full_name)
            return None

        name, epoch, version, release, arch = match.groups()

        if not epoch:
            epoch = 0
        else:
            epoch = int(epoch)

        # Prepare full_version string
        epoch_str = ""
        if epoch != 0:
            epoch_str = f"{epoch}:"

        return RPMPackage(
            name=name,
            epoch=epoch,
            version=version,
            release=release,
            arch=arch,
            full_name=full_name,
            full_version=f"{epoch_str}{version}-{release}.{arch}",
        )

    @staticmethod
    def from_name_and_full_version(name: str, full_version: str):
        if not name or not full_version:
            return None

        name = name.strip()
        full_version = full_version.strip()

        match = _rpm_compile_version.match(full_version)
        if not match:
            logger.warning(
                "The rpm package %s-%s could not be parsed", name, full_version
            )
            return None

        epoch, version, release, arch = match.groups()

        if not epoch:
            epoch = 0
        else:
            epoch = int(epoch)

        return RPMPackage(
            name=name,
            epoch=epoch,
            version=version,
            release=release,
            arch=arch,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
        )
