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

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass(frozen=True)
class Severity:
    origin: str
    date: datetime
    cvss_v2: Optional[str] = None
    cvss_v3: Optional[str] = None


@dataclass(frozen=True)
class Advisory:
    oid: str
    title: str
    creation_date: datetime
    last_modification: datetime
    advisory_id: str
    advisory_xref: str
    severity: Severity
    summary: Optional[str] = None
    insight: Optional[str] = None
    affected: Optional[str] = None
    impact: Optional[str] = None
    cves: List[str] = field(default_factory=list)
    xrefs: List[str] = field(default_factory=list)

    def __hash__(self) -> int:
        # implement hash function for storage in dict, set, etc.
        # use oid for hashing because it is the unique id of an advisory
        # different advisories must have a different oid
        return hash(self.oid)
