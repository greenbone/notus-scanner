# Copyright (C) 2020-2021 Greenbone Networks GmbH
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

from pathlib import Path
from typing import Generator, List

from .loader import AdvisoriesLoader, CsvAdvisoriesLoader
from .messages.result import ResultMessage
from .messages.status import ScanStatus, ScanStatusMessage
from .messaging.publisher import Publisher
from .models.package import Package
from .models.vulnerability import PackageVulnerability

logger = logging.getLogger(__name__)


class NotusScan:
    def __init__(self, advisories_loader: AdvisoriesLoader):
        self._advisories_loader = advisories_loader

    def start_scan(
        self,
        host_ip: str,
        host_name: str,
        operating_system: str,
        installed_packages: List[Package],
    ) -> Generator[PackageVulnerability, None, None]:
        package_advisories = self._advisories_loader.load(operating_system)

        for package in installed_packages:
            package_advisory_list = (
                package_advisories.get_package_advisories_for_package(package)
            )
            for package_advisory in package_advisory_list:
                if package_advisory.package > package:
                    yield PackageVulnerability(
                        host_ip=host_ip,
                        host_name=host_name,
                        package=package,
                        fixed_package=package_advisory.package,
                        advisory=package_advisory.package,
                    )


class NotusScanner:
    def __init__(
        self,
        metadata_directory: Path,
        publisher: Publisher,
    ):
        # hardcode CSV file for now because we don't support other OS yet
        csv_file_path = metadata_directory / "EulerOS.csv"
        if not csv_file_path.is_file():
            logger.error(
                'Could not load advisories from %s. File does not exist.',
                str(csv_file_path),
            )
            return

        self._loader = CsvAdvisoriesLoader(csv_file_path)
        self._publisher = publisher

    def _finish_host(self, scan_id: str, host_ip: str):
        """Send a message to the broker to inform a host is done."""

        try:
            self._publisher.publish_status(
                scan_id=scan_id, host_ip=host_ip, status="done"
            )
        except Exception as e:  # pylint: disable=broad-except
            logger.error(
                "An error occurred while pushing the 'host done' message. "
                "Reason %s",
                str(e),
            )

    def _publish_result(
        self, scan_id: str, vulnerability: PackageVulnerability
    ) -> None:
        report = f"""Vulnerable package: {vulnerability.package.name}
Installed version: {vulnerability.package.full_name}
Fixed version: {vulnerability.fixed_package.full_name}
"""
        message = ResultMessage(
            scan_id=scan_id,
            host_ip=vulnerability.host,
            host_name=vulnerability.hostname,
            oid=vulnerability.advisory.oid,
            value=report,
        )
        self._publisher.publish(message)

    def _publish_status(self, scan_id: str, host_ip: str, status: str):
        message = ScanStatusMessage(
            scan_id=scan_id,
            host_ip=host_ip,
            status=ScanStatus(status),
        )

        self._publisher.publish(message)

    def run_scan(
        self,
        scan_id: str,
        host_ip: str,
        host_name: str,
        os_release: str,
        package_list: List[str],
    ):
        """Handle the data necessary to start a scan,
        received via mqtt and run the scan."""

        installed_packages = [Package(name) for name in package_list]
        scan = NotusScan(advisories_loader=self._loader)
        i = 0
        for vulnerability in scan.start_scan(
            host_ip=host_ip,
            host_name=host_name,
            operating_system=os_release,
            installed_packages=installed_packages,
        ):
            i += 1
            self._publish_result(scan_id, vulnerability)

        logger.info("Total number of vulnerable packages -> %d", i)

        self._finish_host(scan_id, host_ip)
