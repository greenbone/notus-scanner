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
from socket import error as SocketError
from typing import Generator, Iterable, Optional

from paramiko import (
    AuthenticationException,
    AutoAddPolicy,
    BadHostKeyException,
    MissingHostKeyPolicy,
    RejectPolicy,
    SSHClient,
    SSHException,
    WarningPolicy,
)
from notus.scanner.models.os.debian import Debian
from notus.scanner.models.os.distribution import Distribution
from notus.scanner.models.os.euleros import EulerOS
from notus.scanner.models.os.suse import SuSE

from notus.scanner.models.packages.deb import DEBPackage

from .errors import AdvisoriesLoadingError
from .loader import AdvisoriesLoader
from .messages.message import Message
from .messages.result import ResultMessage
from .messages.start import ScanHostsMessage, ScanStartMessage
from .messages.status import ScanStatus, ScanStatusMessage
from .messaging.publisher import Publisher
from .models.packages.package import Package, PackageAdvisories, PackageType
from .models.packages.rpm import RPMPackage
from .models.vulnerability import PackageVulnerability


SUPPORTED_DISTRIBUTIONS: list[type[Distribution]] = [Debian, EulerOS, SuSE]
SSH_POLICY: dict[str, type[MissingHostKeyPolicy]] = {
    "add": AutoAddPolicy,
    "warn": WarningPolicy,
    "reject": RejectPolicy,
}

logger = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)


class NotusScanner:
    def __init__(
        self,
        loader: AdvisoriesLoader,
        publisher: Publisher,
        ssh_policy: SSH_POLICY,
        ssh_host_keyfile: str,
        ssh_system_host_keys: bool,
    ):
        self._loader = loader
        self._publisher = publisher
        self._ssh_policy = ssh_policy
        self._ssh_host_keyfile = ssh_host_keyfile
        self._ssh_system_host_keys = ssh_system_host_keys

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
        report = f"""Vulnerable package: {vulnerability.package.name}
Installed version: {vulnerability.package.full_name}
Fixed version: {vulnerability.fixed_package.full_name}"""
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
    ) -> Generator[PackageVulnerability, None, None]:

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
                        advisory=package_advisory.advisory,
                    )

    def scan_hosts_ssh(self, msg: ScanHostsMessage) -> None:
        """Handles Data given with ScanHostMessage and runs scan. The Message
        must contain credentials to setup a SSH connection to get the required
        os release and package list. If no SSH cannot connect to the host, it
        just get skipped."""
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(self._ssh_policy())
        if self._ssh_host_keyfile:
            ssh.load_host_keys(self._ssh_host_keyfile)
        if self._ssh_system_host_keys:
            ssh.load_system_host_keys()

        for ip, host in msg.hosts.items():
            try:
                if msg.ssh_key:
                    ssh.connect(
                        hostname=ip,
                        port=msg.ssh_port,
                        username=msg.ssh_login,
                        password=msg.ssh_password,
                        pkey=msg.ssh_key,
                        look_for_keys=False,
                    )
                else:
                    ssh.connect(
                        hostname=ip,
                        port=msg.ssh_port,
                        username=msg.ssh_login,
                        password=msg.ssh_password,
                        look_for_keys=False,
                        timeout=3,
                    )
                os = None
                for dist in SUPPORTED_DISTRIBUTIONS:
                    os = dist.get_os(ssh)
                    if os is not None:
                        pl = dist.gather_package_list(ssh)
                        break
                ssh.close()

                if os is not None and pl:
                    self.run_scan(msg.scan_id, ip, host, os, pl)
                else:
                    logger.debug(
                        "Unable to scan %s. The OS is probably not supported"
                        " yet.",
                        ip,
                    )
            except (
                BadHostKeyException,
                AuthenticationException,
                SSHException,
                SocketError,
            ) as e:
                logger.debug(
                    "Unable to establish SSH connection for %s. Host is"
                    " excluded from scan. Error was: %s",
                    ip,
                    e,
                )

    def scan_host_package_list(self, msg: ScanStartMessage) -> None:
        """Handles Data given with ScanStartMessage and runs scan. The Message
        must contains the required os release and package list."""
        self.run_scan(
            msg.scan_id,
            msg.host_ip,
            msg.host_name,
            msg.os_release,
            msg.package_list,
        )

    def run_scan(
        self,
        scan_id: str,
        host_ip: str,
        host_name: Optional[str],
        os_release: str,
        package_list: list[str],
    ) -> None:
        """Runs a scan with given data."""

        if not os_release:
            logger.error(
                "Unable to start scan for %s: The field os_release is empty",
                host_ip,
            )
            return
        if not package_list:
            logger.error(
                "Unable to start scan for %s: The field package_list is empty",
                host_ip,
            )
            return

        # Get advisory information from disk
        try:
            package_advisories = self._loader.load_package_advisories(
                os_release
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
                host_ip,
                os_release,
            )
            return

        # Determine package type
        package_type = package_advisories.package_type

        package_class = (
            DEBPackage if package_type == PackageType.DEB else RPMPackage
        )
        may_installed = [
            package_class.from_full_name(name) for name in package_list
        ]
        # a package in may_installed can only be None when .from_full_name fails
        # they both log a warning when they're unable to parse that hence it
        # is safe to silently remove them
        installed_packages: Iterable[Package] = (
            package for package in may_installed if package is not None
        )

        self._start_host(scan_id, host_ip)

        i = 0
        try:
            for vulnerability in self._start_scan(
                host_ip=host_ip,
                host_name=host_name,
                installed_packages=installed_packages,
                package_advisories=package_advisories,
            ):
                i += 1
                self._publish_result(scan_id, vulnerability)

            logger.info("Total number of vulnerable packages -> %d", i)

            self._finish_host(scan_id, host_ip)

        except AdvisoriesLoadingError as e:
            logger.error(
                "Scan for %s %s with %s could not be started. Error was %s",
                host_ip,
                host_name or "",
                os_release,
                e,
            )
