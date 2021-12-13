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

from typing import Dict, Optional
import logging
from ..models.packages.deb import DEBPackage
from ..models.packages.package import PackageAdvisories, PackageType
from ..models.packages.package import AdvisoryReference, PackageAdvisories
from ..models.packages.rpm import RPMPackage

logger = logging.getLogger(__name__)


class AdvisoriesLoader:
    def load_advisory(self, operating_system: str) -> Optional[Dict]:
        raise NotImplementedError()

    def load_package_advisories(
        self, data: Optional[Dict]
    ) -> PackageAdvisories:
        package_advisories = PackageAdvisories()
        if not data:
            return package_advisories
        operating_system = data.get("product_name", "")
        package_type_id = data.get("package_type", "")
        try:
            package_type = PackageType[package_type_id.upper()]
        except KeyError:
            logger.log(
                logging.WARN, "%s invalid package type.", package_type_id
            )
            return package_advisories

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

            advisory = AdvisoryReference(oid)

            for package_dict in fixed_packages:
                full_name = package_dict.get("full_name")
                if full_name:
                    if package_type == PackageType.DEB:
                        package = DEBPackage.from_full_name(full_name)
                    else:
                        package = RPMPackage.from_full_name(full_name)
                else:
                    if package_type == PackageType.DEB:
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
                        operating_system,
                    )
                    continue

                package_advisories.add_advisory_for_package(package, advisory)

        return package_advisories
