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

import json
import logging

from datetime import datetime, timezone
from json.decoder import JSONDecodeError
from pathlib import Path

from ..errors import AdvisoriesLoadingError
from ..models.advisory import (
    Advisory,
    PackageAdvisories,
    Severity,
)
from ..models.package import parse_rpm_package

from .loader import AdvisoriesLoader

logger = logging.getLogger(__name__)


def _get_operating_system_file_name(operating_system: str) -> str:
    return operating_system.strip().replace(' ', '_').lower()


class JSONAdvisoriesLoader(AdvisoriesLoader):
    def __init__(self, advisories_directory_path: Path):
        self._advisories_directory_path = advisories_directory_path

    def load(self, operating_system: str) -> PackageAdvisories:
        os_file_name = _get_operating_system_file_name(operating_system)
        json_file_path = (
            self._advisories_directory_path / f"{os_file_name}.notus"
        )
        if not json_file_path.exists():
            raise AdvisoriesLoadingError(
                f'Could not load advisories from {json_file_path.absolute()}. '
                'File does not exist.'
            )

        package_advisories = PackageAdvisories()
        if json_file_path.stat().st_size < 2:
            # the minimim size of a json file is 2 bytes ({} or [])
            return package_advisories

        with json_file_path.open('r', encoding="utf-8") as f:
            try:
                json_data = json.load(f)
            except JSONDecodeError as e:
                raise AdvisoriesLoadingError(
                    f'Could not load advisories from '
                    f'{json_file_path.absolute()}. Error in line {e.lineno} '
                    f'while decoding JSON data.'
                ) from None

        for advisory_data in json_data.get("advisories", []):
            if not "oid" in advisory_data:
                logger.error('No OID found for JSON advisory %s', advisory_data)
                continue

            try:
                # parse required data
                oid = advisory_data['oid']
                title = advisory_data['title']
                creation_date = datetime.fromtimestamp(
                    advisory_data['creation_date'], timezone.utc
                )
                last_modification = datetime.fromtimestamp(
                    advisory_data['last_modification'], timezone.utc
                )
                advisory_id = advisory_data['advisory_id']
                advisory_xref = advisory_data['advisory_xref']
                fixed_packages = advisory_data['fixed_packages']
                severity_data = advisory_data['severity']
                severity_origin = severity_data['origin']
                severity_date = datetime.fromtimestamp(
                    severity_data['date'], tz=timezone.utc
                )
            except (KeyError, TypeError) as e:
                logger.warning(
                    'Error while parsing %s from %s. Error was %s',
                    advisory_data,
                    str(json_file_path.absolute()),
                    e,
                )
                continue

            # parse optional data
            summary = advisory_data.get('summary')
            insight = advisory_data.get('insight')
            affected = advisory_data.get('affected')
            impact = advisory_data.get('impact')
            xrefs = advisory_data.get('xrefs', [])
            cves = advisory_data.get('cves', [])
            cvss_v2 = severity_data.get('cvss_v2')
            cvss_v3 = severity_data.get('cvss_v3')

            severity = Severity(
                origin=severity_origin,
                date=severity_date,
                cvss_v2=cvss_v2,
                cvss_v3=cvss_v3,
            )
            advisory = Advisory(
                oid=oid,
                title=title,
                creation_date=creation_date,
                last_modification=last_modification,
                advisory_id=advisory_id,
                advisory_xref=advisory_xref,
                severity=severity,
                summary=summary,
                insight=insight,
                affected=affected,
                impact=impact,
                xrefs=xrefs,
                cves=cves,
            )

            for package_name in fixed_packages:
                package = parse_rpm_package(package_name)
                package_advisories.add_advisory_for_package(package, advisory)

        return package_advisories
