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
from typing import Iterable, List, Set, Optional

from notus.scanner.models.packages import package_class_by_type

from .errors import AdvisoriesLoadingError
from .loader import AdvisoriesLoader
from .messages.message import Message
from .messages.result import ResultMessage
from .messages.start import ScanStartMessage
from .messages.status import ScanStatus, ScanStatusMessage
from .messaging.publisher import Publisher
from .models.packages.package import Package, PackageAdvisories, PackageAdvisory
from .models.vulnerability import Vulnerabilities, Vulnerability

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

    def _publish_results(
        self,
        scan_id: str,
        host_ip: str,
        host_name: str,
        vulnerabilities: Vulnerabilities,
    ) -> None:
        for oid, vulnerability in vulnerabilities.get().items():
            report = ""
            fixed_packages: List[PackageAdvisory]
            for package, fixed_packages in vulnerability.get().items():
                fixed_package = fixed_packages.pop(0)
                report = (
                    report + f"\n{'Vulnerable package:':<22}{package.name}\n"
                    f"{'Installed version:':<22}{package.full_name}\n"
                    f"{'Fixed version:':<20}{fixed_package.symbol:>2}"
                    f"{fixed_package.package.full_name}\n"
                )
                for fixed_package in fixed_packages:
                    report = (
                        report + f"{'':<20}{fixed_package.symbol:>2}"
                        f"{fixed_package.package.full_name}\n"
                    )

            message = ResultMessage(
                scan_id=scan_id,
                host_ip=host_ip,
                host_name=host_name,
                oid=oid,
                value=report,
            )
            self._publish(message)

    @staticmethod
    def _check_package(
        package: Package, package_advisory_list: Set[PackageAdvisory]
    ) -> Optional[Vulnerability]:

        vul = Vulnerability()
        for package_advisory in package_advisory_list:
            logger.debug(
                "%s verify package %s %s %s",
                package_advisory.oid,
                package,
                package_advisory.symbol,
                package_advisory.package,
            )
            is_vulnerable = package_advisory.is_vulnerable(package)
            if is_vulnerable is None:
                continue
            elif not is_vulnerable:
                return

            vul.add(package, package_advisory)

        return vul

    def _start_scan(
        self,
        installed_packages: Iterable[Package],
        package_advisories: PackageAdvisories,
    ) -> Vulnerabilities:

        vulnerabilities = Vulnerabilities()

        for package in installed_packages:
            package_advisory_oids = (
                package_advisories.get_package_advisories_for_package(package)
            )
            for oid, package_advisory_list in package_advisory_oids.items():

                vul = self._check_package(package, package_advisory_list)
                if vul and vul.vulnerability:
                    vulnerabilities.add(oid, vul)

        return vulnerabilities

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

        logger.debug(
            "Loaded advisories for %i packages", len(package_advisories)
        )

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

        logger.info(
            "Start to identify vulnerable packages for %s (%s)",
            message.host_ip,
            message.host_name,
        )
        try:
            vulnerabilities = self._start_scan(
                installed_packages=installed_packages,
                package_advisories=package_advisories,
            )
            self._publish_results(
                message.scan_id,
                message.host_ip,
                message.host_name,
                vulnerabilities,
            )

            logger.info(
                "Total number of vulnerable packages -> %d",
                len(vulnerabilities),
            )

            self._finish_host(message.scan_id, message.host_ip)

        except AdvisoriesLoadingError as e:
            logger.error(
                "Scan for %s %s with %s could not be started. Error was %s",
                message.host_ip,
                message.host_name or "",
                message.os_release,
                e,
            )
