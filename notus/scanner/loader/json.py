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

from json.decoder import JSONDecodeError
from pathlib import Path
from typing import Callable

from notus.scanner.models.packages.deb import DEBPackage

from ..errors import AdvisoriesLoadingError
from ..models.packages.package import (
    AdvisoryReference,
    PackageAdvisories,
)
from ..models.packages.rpm import RPMPackage
from ..models.packages.deb import DEBPackage
from .loader import AdvisoriesLoader

logger = logging.getLogger(__name__)


def _get_operating_system_file_name(operating_system: str) -> str:
    return operating_system.strip().replace(" ", "_").lower()


class JSONAdvisoriesLoader(AdvisoriesLoader):
    def __init__(
        self, advisories_directory_path: Path, verify: Callable[[Path], bool]
    ):
        self._advisories_directory_path = advisories_directory_path
        self._verify = verify

    def load_package_advisories(
        self, operating_system: str
    ) -> PackageAdvisories:
        os_file_name = _get_operating_system_file_name(operating_system)
        json_file_path = (
            self._advisories_directory_path / f"{os_file_name}.notus"
        )
        if not json_file_path.exists():
            raise AdvisoriesLoadingError(
                f"Could not load advisories from {json_file_path.absolute()}. "
                "File does not exist."
            )
        if not self._verify(json_file_path):
            raise AdvisoriesLoadingError(
                f"Could not load advisories from {json_file_path.absolute()}. "
                "File verification failed."
            )

        package_advisories = PackageAdvisories()
        if json_file_path.stat().st_size < 2:
            # the minimim size of a json file is 2 bytes ({} or [])
            return package_advisories

        with json_file_path.open("r", encoding="utf-8") as f:
            try:
                json_data = json.load(f)
            except JSONDecodeError as e:
                raise AdvisoriesLoadingError(
                    "Could not load advisories from "
                    f"{json_file_path.absolute()}. Error in line {e.lineno} "
                    "while decoding JSON data."
                ) from None

        for advisory_data in json_data.get("advisories", []):
            if not "oid" in advisory_data:
                logger.error("No OID found for JSON advisory %s", advisory_data)
                continue

            try:
                # parse required data
                oid = advisory_data["oid"]
                fixed_packages = advisory_data["fixed_packages"]
            except (KeyError, TypeError) as e:
                logger.warning(
                    "Error while parsing %s from %s. Error was %s",
                    advisory_data,
                    str(json_file_path.absolute()),
                    e,
                )
                continue

            advisory = AdvisoryReference(oid)

            for package_dict in fixed_packages:
                full_name = package_dict.get("full_name")
                if full_name:
                    if operating_system.find("debian") != -1:
                        package = DEBPackage.from_full_name(full_name)
                    else:
                        package = RPMPackage.from_full_name(full_name)
                else:
                    if "debian" in operating_system:
                        package = DEBPackage.from_name_and_full_version(
                            package_dict.get("name"),
                            package_dict.get("full_version"),
                        )
                    else:
                        package = RPMPackage.from_name_and_full_version(
                            package_dict.get("name"),
                            package_dict.get("full_version"),
                        )
                if not package:
                    logger.warning(
                        "Could not parse fixed package information from %s "
                        "in %s",
                        package_dict,
                        json_file_path.absolute(),
                    )
                    continue

                package_advisories.add_advisory_for_package(package, advisory)

        return package_advisories
