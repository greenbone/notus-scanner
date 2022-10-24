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

import json
import logging
from json.decoder import JSONDecodeError
from pathlib import Path
from typing import Callable, Dict, Optional

from ..errors import AdvisoriesLoadingError
from ..models.packages import package_class_by_type
from ..models.packages.package import PackageAdvisories, PackageType
from .gpg_sha_verifier import VerificationResult
from .loader import AdvisoriesLoader

logger = logging.getLogger(__name__)


def _get_operating_system_file_name(operating_system: str) -> str:
    return operating_system.strip().replace(" ", "_").lower()


class JSONAdvisoriesLoader(AdvisoriesLoader):
    def __init__(
        self,
        advisories_directory_path: Path,
        verify: Callable[[Path], VerificationResult],
    ):
        self._advisories_directory_path = advisories_directory_path
        self._verify = verify

    def __load_data(self, operating_system: str) -> Optional[Dict]:
        os_file_name = _get_operating_system_file_name(operating_system)
        json_file_path = (
            self._advisories_directory_path / f"{os_file_name}.notus"
        )
        # since the data is coming from the outside it should not crash
        # on wrongfully send data instead print a warning and return None
        if not json_file_path.exists():
            logger.log(
                logging.WARNING,
                "Could not load advisories from %s. File does not exist.",
                json_file_path.absolute(),
            )
            return None
        # If there is a file but unable to verify it could be that the feed
        # is corrupted and the application should stop
        verify_result = self._verify(json_file_path)
        if verify_result == VerificationResult.SUCCESS:
            logger.debug("File '%s' verification successful.", json_file_path)
        else:
            reason = (
                "File verification failed."
                if verify_result != VerificationResult.INVALID_NAME
                else "OS name does not match filename."
            )
            raise AdvisoriesLoadingError(
                f"could not load advisories from {json_file_path.absolute()}. "
                f"{reason}"
            )

        if json_file_path.stat().st_size < 2:
            # the minimum size of a json file is 2 bytes ({} or [])
            return None

        with json_file_path.open("r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except JSONDecodeError as e:
                raise AdvisoriesLoadingError(
                    "Could not load advisories from "
                    f"{json_file_path.absolute()}. Error in line {e.lineno} "
                    "while decoding JSON data."
                ) from None

    def load_package_advisories(
        self, operating_system: str
    ) -> Optional[PackageAdvisories]:
        data = self.__load_data(operating_system=operating_system)
        if not data:
            return None
        package_type_id = data.get("package_type", "")
        try:
            package_type = PackageType(package_type_id)
        except ValueError:
            logger.warning("%s invalid package type.", package_type_id)
            return None
        package_advisories = PackageAdvisories(package_type)
        package_class = package_class_by_type(package_type)
        if not package_class:
            logger.warning("%s has no package implementation", package_type_id)
            return None

        for advisory_data in data.get("advisories", []):
            if not "oid" in advisory_data:
                logger.error("No OID found for JSON advisory %s", advisory_data)
                continue

            try:
                # parse required data
                oid = advisory_data["oid"]
                fixed_packages = advisory_data["fixed_packages"]
            except (KeyError, TypeError) as e:
                logger.warning(
                    "Error while parsing %s for %s. Error was %s",
                    advisory_data,
                    operating_system,
                    e,
                )
                continue

            advisory = oid

            for package_dict in fixed_packages:
                full_name = package_dict.get("full_name")
                if full_name:
                    package = package_class.from_full_name(full_name)
                else:
                    package = package_class.from_name_and_full_version(
                        package_dict.get("name"),
                        package_dict.get("full_version"),
                    )
                if not package:
                    logger.warning(
                        "Could not parse fixed package information from %s "
                        "in %s",
                        package_dict,
                        operating_system,
                    )
                    continue

                package_advisories.add_advisory_for_package(
                    package, advisory, package_dict.get("specifier")
                )

        return package_advisories
