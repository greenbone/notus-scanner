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

from abc import abstractmethod
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Dict, Set

from ...errors import PackageError


logger = logging.getLogger(__name__)

# Return values:
#   a_newer: a is newer than b, return 1
#   _B_NEWER: b is newer than a, return -1
#   _A_EQ_B: a and b are equal, return 0
A_NEWER = 1
B_NEWER = -1
A_EQ_B = 0


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
    AARCH64_ILP32 = "aarch64_ilp32"
    UNKNOWN = "UNKNOWN"
    NOTSET = "NOTSET"


@dataclass
class Package:
    "Base class for different Package types"
    name: str
    full_name: str
    full_version: str

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, type(self)):
            raise PackageError(f"Can't compare {self!r} to {other!r}.")

        return self._compare(other) > 0

    def __hash__(self) -> int:
        # allow to hash the package
        # the full name identifies the package
        return hash(self.full_name)

    @abstractmethod
    def _compare(self, other: Any) -> bool:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def from_full_name(full_name: str):
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def from_name_and_full_version(name: str, full_version: str):
        raise NotImplementedError()


@dataclass(frozen=True)
class AdvisoryReference:
    """A reference to a vulnerability advisory"""

    oid: str


@dataclass(frozen=True, unsafe_hash=True)
class PackageAdvisory:
    """Connects a package with an advisory"""

    package: Package
    advisory: AdvisoryReference


@dataclass(frozen=True)
class PackageAdvisories:
    """Container for mapping a package name to a set of advisories for this
    package"""

    advisories: Dict[str, Set[PackageAdvisory]] = field(default_factory=dict)

    def get_package_advisories_for_package(
        self, package: Package
    ) -> Set[PackageAdvisory]:
        return self.advisories.get(package.name) or set()

    def add_advisory_for_package(
        self, package: Package, advisory: AdvisoryReference
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
