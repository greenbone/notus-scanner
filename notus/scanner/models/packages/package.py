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

from abc import abstractmethod
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Set, Optional

from ...errors import PackageError


logger = logging.getLogger(__name__)


class PackageType(Enum):
    RPM = "rpm"
    DEB = "deb"
    EBUILD = "ebuild"


class PackageComparision(Enum):
    EQUAL = 0  # a and b are equal
    A_NEWER = 1  # a is newer than b
    B_NEWER = 2  # b is newer than a
    # a and b are not compareable. e.g. different architectures
    NOT_COMPARABLE = 3


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

    def __guard_cmp(self, other: Any):
        if not isinstance(other, type(self)):
            raise PackageError(f"Can't compare {self!r} to {other!r}.")

    def __gt__(self, other: Any) -> bool:
        self.__guard_cmp(other)
        return self._compare(other) == PackageComparision.A_NEWER

    def __lt__(self, other: Any) -> bool:
        self.__guard_cmp(other)
        return self._compare(other) == PackageComparision.B_NEWER

    def __eq__(self, other: Any) -> bool:
        self.__guard_cmp(other)
        return self._compare(other) == PackageComparision.EQUAL

    def __ge__(self, other: Any) -> bool:
        return self.__gt__(other) or self.__eq__(other)

    def __le__(self, other: Any) -> bool:
        return self.__lt__(other) or self.__eq__(other)

    def __hash__(self) -> int:
        # allow to hash the package
        # the full name identifies the package
        return hash(self.full_name)

    @abstractmethod
    def _compare(self, other: Any) -> PackageComparision:
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
class Verifier:
    symbol: str
    _verifier: Callable[[Package, Package], bool]

    def __name__(self) -> str:
        return self.symbol

    def verify(self, expected: Package, actual: Package) -> bool:
        return self._verifier(expected, actual)


@dataclass(frozen=True)
class AdvisoryReference:
    """A reference to a vulnerability advisory"""

    oid: str


@dataclass(frozen=True, unsafe_hash=True)
class PackageAdvisory:
    """Connects a package with an advisory"""

    package: Package
    advisory: AdvisoryReference
    is_vulnerable: Callable[[Package], bool] = field(compare=False, hash=False)


@dataclass(frozen=True)
class PackageAdvisories:
    """Container for mapping a package name to a set of advisories for this
    package"""

    package_type: PackageType
    advisories: Dict[str, Set[PackageAdvisory]] = field(default_factory=dict)

    def get_package_advisories_for_package(
        self, package: Package
    ) -> Set[PackageAdvisory]:
        return self.advisories.get(package.name) or set()

    @staticmethod
    def is_vulnerable_from_symbol(symbol: Optional[str]):
        """
        is_vulnerable_from_symbol returns either a Verifier when the symbol
        identifier contains a known operand or or >= if not.
        """
        if not symbol or symbol.startswith(">="):
            return Verifier(">=", lambda a, b: a > b)
        if symbol.startswith("<="):
            return Verifier("<=", lambda a, b: a < b)
        if symbol.startswith("="):
            return Verifier("=", lambda a, b: a != b)
        if symbol.startswith("<"):
            return Verifier("<", lambda a, b: a <= b)
        if symbol.startswith(">"):
            return Verifier(">", lambda a, b: a >= b)

        return Verifier(">=", lambda a, b: a > b)

    def add_advisory_for_package(
        self,
        package: Package,
        advisory: AdvisoryReference,
        verifier: Optional[str],
    ) -> None:

        advisories = self.get_package_advisories_for_package(package)
        use_verifier = self.is_vulnerable_from_symbol(verifier)
        is_vulnerable = lambda other: use_verifier.verify(package, other)

        advisories.add(PackageAdvisory(package, advisory, is_vulnerable))
        self.advisories[package.name] = advisories

    def __len__(self) -> int:
        return len(self.advisories)
