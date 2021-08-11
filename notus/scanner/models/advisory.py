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

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set

from .package import Package


@dataclass(frozen=True)
class Advisory:
    oid: str
    title: str
    creation_date: datetime
    last_modification: datetime
    advisory_id: str
    advisory_xref: str
    severity_origin: str
    severity_date: datetime
    severity_vector_v2: Optional[str] = None
    severity_vector_v3: Optional[str] = None
    summary: Optional[str] = None
    insight: Optional[str] = None
    affected: Optional[str] = None
    impact: Optional[str] = None
    cve_list: List[str] = field(default_factory=list)
    xrefs: List[str] = field(default_factory=list)

    def __hash__(self) -> int:
        # implement hash function for storage in dict, set, etc.
        # use oid for hashing because it is the unique id of an advisory
        # different advisories must have a different oid
        return hash(self.oid)


@dataclass(frozen=True, unsafe_hash=True)
class PackageAdvisory:
    package: Package
    advisory: Advisory


@dataclass(frozen=True)
class PackageAdvisories:
    advisories: Dict[str, Set[PackageAdvisory]] = field(default_factory=dict)

    def get_package_advisories_for_package(
        self, package: Package
    ) -> Set[PackageAdvisory]:
        return self.advisories.get(package.name) or set()

    def add_advisory_for_package(
        self, package: Package, advisory: Advisory
    ) -> None:
        advisories = self.get_package_advisories_for_package(package)
        advisories.add(PackageAdvisory(package, advisory))
        self.advisories[package.name] = advisories


@dataclass(frozen=True)
class OperatingSystemAdvisories:
    advisories: Dict[str, PackageAdvisories] = field(default_factory=dict)

    def get_package_advisories(
        self, operating_system: str
    ) -> Optional[PackageAdvisories]:
        return self.advisories.get(operating_system)

    def set_package_advisories(
        self, operating_system: str, package_advisories: PackageAdvisories
    ) -> None:
        self.advisories[operating_system] = package_advisories
