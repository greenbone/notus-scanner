# Copyright (C) 2020-2022 Greenbone Networks GmbH
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
from typing import Dict, Iterable, List
from notus.scanner.models.packages import package_class_by_type

from .errors import AdvisoriesLoadingError
from .loader import AdvisoriesLoader
from .messages.message import Message
from .messages.result import ResultMessage
from .messages.start import ScanStartMessage
from .messages.status import ScanStatus, ScanStatusMessage
from .messaging.publisher import Publisher
from .models.packages.package import Package, PackageAdvisories
from .models.vulnerability import PackageVulnerability

logger = logging.getLogger(__name__)


class NotusScanner:
    def __init__(
        self,
        loader: AdvisoriesLoader,
        publisher: Publisher,
    ):
        self._loader = loader
        self._publisher = publisher

    def _publish(self, message: Message):
        """Try to publish a message

        Ensures that a failure during publishing doesn't stop the scan or daemon
        """
        try:
            self._publisher.publish(message)
        except Exception as e:  # pylint: disable=broad-except
            logger.error(
                "An error occurred while publishing a %s message. Reason %s",
                type(message),
                str(e),
            )

    def _finish_host(self, scan_id: str, host_ip: str):
        """Send a message to the broker to inform a host is done."""

        scan_status_message = ScanStatusMessage(
            scan_id=scan_id, host_ip=host_ip, status=ScanStatus.FINISHED
        )
        self._publish(scan_status_message)

    def _start_host(self, scan_id: str, host_ip: str):
        """Send a message to the broker to inform a host scan has started."""
        scan_status_message = ScanStatusMessage(
            scan_id=scan_id, host_ip=host_ip, status=ScanStatus.RUNNING
        )
        self._publish(scan_status_message)

    def _publish_result(
        self, scan_id: str, vulnerability: PackageVulnerability
    ) -> None:
        report = ""
        for package, fixed_package in vulnerability.packages.items():
            report = (
                report
                + f"""
Vulnerable package: {package.name}
Installed version:  {package.full_name}
Fixed version:      {fixed_package.full_name}
"""
            )
        message = ResultMessage(
            scan_id=scan_id,
            host_ip=vulnerability.host_ip,
            host_name=vulnerability.host_name,
            oid=vulnerability.advisory.oid,
            value=report,
        )
        self._publish(message)

    def _start_scan(
        self,
        host_ip: str,
        host_name: str,
        installed_packages: Iterable[Package],
        package_advisories: PackageAdvisories,
    ) -> List[PackageVulnerability]:
        vulnerabilities: Dict[str, PackageVulnerability] = {}
        for package in installed_packages:
            package_advisory_list = (
                package_advisories.get_package_advisories_for_package(package)
            )
            for package_advisory in package_advisory_list:
                if package_advisory.is_vulnerable(package):
                    oid = package_advisory.advisory.oid
                    if oid in vulnerabilities:
                        vulnerabilities[oid].add_package(
                            package, package_advisory.package
                        )
                    else:
                        vulnerabilities[oid] = PackageVulnerability(
                            host_ip=host_ip,
                            host_name=host_name,
                            package=package,
                            fixed_package=package_advisory.package,
                            advisory=package_advisory.advisory,
                        )

        return vulnerabilities.values()

    def run_scan(
        self,
        message: ScanStartMessage,
    ) -> None:
        """Handle the data necessary to start a scan,
        received via mqtt and run the scan."""

        # Check if all necessary information to run a scan are given
        if not message:
            logger.error(
                "Unable to start scan for %s: The message seems to be empty",
                message.host_ip,
            )
            return
        if not message.os_release:
            logger.error(
                "Unable to start scan for %s: The field os_release is empty",
                message.host_ip,
            )
            return
        if not message.package_list:
            logger.error(
                "Unable to start scan for %s: The field package_list is empty",
                message.host_ip,
            )
            return

        # Get advisory information from disk
        try:
            package_advisories = self._loader.load_package_advisories(
                message.os_release
            )
        except AdvisoriesLoadingError as e:
            logger.error("Unable to load package advisories. Error was %s", e)
            return

        if not package_advisories:
            # Probably a wrong or not supported OS-release
            logger.error(
                "Unable to start scan for %s: No advisories for OS-release %s"
                " found. Check if the OS-release is correct and the"
                " corresponding advisories are given.",
                message.host_ip,
                message.os_release,
            )
            return

        # Determine package type
        package_type = package_advisories.package_type

        package_class = package_class_by_type(package_type)
        if not package_class:
            logger.error(
                "Unable to start scan for %s: No package implementation for "
                "OS-release %s found. Check if the OS-release is correct.",
                message.host_ip,
                message.os_release,
            )
            return

        may_installed = [
            package_class.from_full_name(name) for name in message.package_list
        ]
        # a package in may_installed can only be None when .from_full_name fails
        # they both log a warning when they're unable to parse that hence it
        # is safe to silently remove them
        installed_packages: Iterable[Package] = (
            package for package in may_installed if package is not None
        )

        self._start_host(message.scan_id, message.host_ip)

        i = 0
        try:
            for vulnerability in self._start_scan(
                host_ip=message.host_ip,
                host_name=message.host_name,
                installed_packages=installed_packages,
                package_advisories=package_advisories,
            ):
                i += 1
                self._publish_result(message.scan_id, vulnerability)

            logger.info("Total number of vulnerable packages -> %d", i)

            self._finish_host(message.scan_id, message.host_ip)

        except AdvisoriesLoadingError as e:
            logger.error(
                "Scan for %s %s with %s could not be started. Error was %s",
                message.host_ip,
                message.host_name or "",
                message.os_release,
                e,
            )
