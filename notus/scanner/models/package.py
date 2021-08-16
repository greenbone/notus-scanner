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

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class Architecture(Enum):
    NOARCH = 'noarch'
    SOURCE = 'src'
    ALL = 'all'
    I386 = 'i386'
    I586 = 'i586'
    I686 = 'i686'
    X86_64 = 'x86_64'
    ARMV7L = 'armv7l'
    ARMV6L = 'armv6l'
    AARCH64 = 'aarch64'
    AMD64 = 'amd64'
    IA64 = 'ia64'
    PPC = 'ppc'
    PPC64 = 'ppc64'
    PPC64LE = 'ppc64le'
    S390 = 's390'
    S390X = 's390x'
    UNKNOWN = 'UNKNOWN'
    NOTSET = 'NOTSET'


@dataclass
class Package:
    """Represents a RPM package"""

    name: str
    version: str
    release: str
    arch: Architecture
    full_name: str

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, Package):
            raise ValueError(f"Can't compare {self!r} to {other!r}.")

        if self.arch != other.arch:
            # self is not greater if arch does not match
            # we should not compare packages with different architectures
            return False

        import rpm  # pylint: disable=import-outside-toplevel

        return rpm.labelCompare(  # pylint: disable=no-member
            ('1', self.version, self.release),
            ('1', other.version, other.release),
        )

    def __hash__(self) -> int:
        # allow to hash the package
        # the full name identifies the package
        return hash(self.full_name)


_rpm_compile_no_arch = re.compile('(.*)-([^-]+)-([^-]+)')
_rpm_compile = re.compile(r'(.*)-([^-]+)-([^-]+)\.([^-]+)')


def parse_rpm_package(package_name: str) -> Optional[Package]:
    if not package_name:
        return None

    try:
        name, version, release, architecture = _rpm_compile.match(
            package_name
        ).groups()
        try:
            arch = Architecture(architecture)
        except ValueError:
            arch = Architecture.UNKNOWN
    except AttributeError:
        try:
            name, version, release = _rpm_compile_no_arch.match(
                package_name
            ).groups()
            arch = Architecture.NOTSET
        except AttributeError:
            logger.warning(
                "The rpm package %s could not be parsed", package_name
            )
            return None

    return Package(name, version, release, arch, package_name)
