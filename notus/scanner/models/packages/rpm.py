# slightly adjusted from https://github.com/ihiji/version_utils
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import re
from dataclasses import dataclass
from packaging.version import parse

from .package import (
    Package,
    Architecture,
    PackageComparision,
)

_rpm_re = re.compile(r"(\S+)-(?:(\d*):)?(.*)-(~?\w+[\w.]*)")

_rpm_compile_no_arch = re.compile("(.*)-([^-]+)-([^-]+)")
_rpm_compile = re.compile(r"(.*)-([^-]+)-([^-]+)\.([^-]+)")
_rpm_compile_version = re.compile(r"([^-]+)-([^-]+)\.([^-]+)")

logger = logging.getLogger(__name__)


@dataclass
class RPMPackage(Package):
    """Represents a RPM package"""

    version: str
    release: str
    arch: str

    __hash__ = Package.__hash__

    def _compare(self, other: "RPMPackage") -> PackageComparision:
        if self.arch != other.arch:
            return PackageComparision.NOT_COMPARABLE

        if self.full_version == other.full_version:
            return PackageComparision.EQUAL

        a_ver = parse(self.version)
        b_ver = parse(other.version)
        if a_ver != b_ver:
            return (
                PackageComparision.A_NEWER
                if a_ver > b_ver
                else PackageComparision.B_NEWER
            )
        a_rel = parse(self.release)
        b_rel = parse(other.release)
        return (
            PackageComparision.A_NEWER
            if a_rel > b_rel
            else PackageComparision.B_NEWER
        )

    @staticmethod
    def from_full_name(full_name: str):
        if not full_name:
            return None

        full_name = full_name.strip()

        try:
            name, version, release, architecture = _rpm_compile.match(
                full_name
            ).groups()
            try:
                arch = Architecture(architecture)
            except ValueError:
                arch = Architecture.UNKNOWN
        except AttributeError:
            try:
                name, version, release = _rpm_compile_no_arch.match(
                    full_name
                ).groups()
                arch = Architecture.NOTSET
            except AttributeError:
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
            full_version=f"{version}-{release}.{arch.value}",
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
        version, release, architecture = version_match.groups()

        try:
            arch = Architecture(architecture)
        except ValueError:
            arch = Architecture.UNKNOWN

        return RPMPackage(
            name=name,
            version=version,
            release=release,
            arch=arch,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
        )
