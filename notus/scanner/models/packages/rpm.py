# slightly adjusted from https://github.com/ihiji/version_utils
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import re
from dataclasses import dataclass

from .package import Package, PackageComparison

_rpm_compile_no_arch = re.compile("(.*)-([^-]+)-([^-]+)")
_rpm_compile = re.compile(r"(.*)-([^-]+)-([^-]+)\.([^-]+)")
_rpm_compile_version = re.compile(r"([^-]+)-([^-]+)\.([^-]+)")

logger = logging.getLogger(__name__)

exceptions = [
    "_fips",
    ".ksplice",
]


@dataclass
class RPMPackage(Package):
    """Represents a RPM package"""

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
        if match:
            name, version, release, arch = match.groups()
        else:
            match = _rpm_compile_no_arch.match(full_name)
            if match:
                name, version, release = match.groups()
                arch = ""
            else:
                logger.warning(
                    "The rpm package %s could not be parsed", full_name
                )
                return None

        return RPMPackage(
            name=name,
            version=version,
            release=release,
            arch=arch,
            full_name=full_name,
            full_version=f"{version}-{release}.{arch}",
        )

    @staticmethod
    def from_name_and_full_version(name: str, full_version: str):
        if not name or not full_version:
            return None

        name = name.strip()
        full_version = full_version.strip()

        version_match = _rpm_compile_version.match(full_version)
        if not version_match:
            return None
        version, release, arch = version_match.groups()

        return RPMPackage(
            name=name,
            version=version,
            release=release,
            arch=arch,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
        )
