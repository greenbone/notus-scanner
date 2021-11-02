# Copyright (C) 2021 Greenbone Networks GmbH
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

import logging
import re

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Set

from .rpm import label_compare

logger = logging.getLogger(__name__)

_rpm_compile_no_arch = re.compile("(.*)-([^-]+)-([^-]+)")
_rpm_compile = re.compile(r"(.*)-([^-]+)-([^-]+)\.([^-]+)")
_rpm_compile_version = re.compile(r"([^-]+)-([^-]+)\.([^-]+)")


class Architecture(Enum):
    NOARCH = "noarch"
    SOURCE = "src"
    ALL = "all"
    I386 = "i386"
    I586 = "i586"
    I686 = "i686"
    X86_64 = "x86_64"
    ARMV7L = "armv7l"
    ARMV6L = "armv6l"
    AARCH64 = "aarch64"
    AMD64 = "amd64"
    IA64 = "ia64"
    PPC = "ppc"
    PPC64 = "ppc64"
    PPC64LE = "ppc64le"
    S390 = "s390"
    S390X = "s390x"
    UNKNOWN = "UNKNOWN"
    NOTSET = "NOTSET"


@dataclass
class RPMPackage:
    """Represents a RPM package"""

    name: str
    version: str
    release: str
    arch: Architecture
    full_name: str
    full_version: str

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, RPMPackage):
            raise ValueError(f"Can't compare {self!r} to {other!r}.")

        if self.arch != other.arch:
            # self is not greater if arch does not match
            # we should not compare packages with different architectures
            return False

        return label_compare(
            ("1", self.version, self.release),
            ("1", other.version, other.release),
        )

    def __hash__(self) -> int:
        # allow to hash the package
        # the full name identifies the package
        return hash(self.full_name)

    @staticmethod
    def from_full_name(full_name: str):
        if not full_name:
            return None

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

        version, release, architecture = _rpm_compile_version.match(
            full_version
        ).groups()

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


@dataclass(frozen=True)
class AdvisoryReference:
    """A reference to a vulnerability advisory"""

    oid: str


@dataclass(frozen=True, unsafe_hash=True)
class PackageAdvisory:
    """Connects a package with an advisory"""

    package: RPMPackage
    advisory: AdvisoryReference


@dataclass(frozen=True)
class PackageAdvisories:
    """Container for mapping a package name to a set of advisories for this
    package"""

    advisories: Dict[str, Set[PackageAdvisory]] = field(default_factory=dict)

    def get_package_advisories_for_package(
        self, package: RPMPackage
    ) -> Set[PackageAdvisory]:
        return self.advisories.get(package.name) or set()

    def add_advisory_for_package(
        self, package: RPMPackage, advisory: AdvisoryReference
    ) -> None:
        advisories = self.get_package_advisories_for_package(package)
        advisories.add(PackageAdvisory(package, advisory))
        self.advisories[package.name] = advisories

    def __len__(self) -> int:
        return len(self.advisories)


@dataclass(frozen=True)
class OperatingSystemAdvisories:
    """Mapping of operating systems to a list of package based advisories"""

    advisories: Dict[str, PackageAdvisories] = field(default_factory=dict)

    def get_package_advisories(
        self, operating_system: str
    ) -> PackageAdvisories:
        return self.advisories.get(operating_system) or PackageAdvisories()

    def set_package_advisories(
        self, operating_system: str, package_advisories: PackageAdvisories
    ) -> None:
        self.advisories[operating_system] = package_advisories

    def __len__(self) -> int:
        return len(self.advisories)
