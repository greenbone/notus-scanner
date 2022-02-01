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

import logging
import re
from typing import List, Optional
from paramiko import SSHClient
from .distribution import Distribution

logger = logging.getLogger(__name__)

# EulerOS 2.0
_euler_re = re.compile(
    r"EulerOS release ([0-9]+\.[0-9]+)\s?(\((SP[0-9]+)(x86_64)?\))?"
)
# EulerOS Virtualzations
_euler_v_re = re.compile(r"EulerOS Virtualization ([a-zA-Z0-9 ]+) ([0-9.]+)")


class EulerOS(Distribution):
    @staticmethod
    def get_os(ssh: SSHClient) -> Optional[str]:
        # Try EulerOS
        os = None
        rls = EulerOS.command(ssh, "cat /etc/euleros-release")
        if rls.find("EulerOS release") >= 0:
            # Euler OS release 2.0 ...
            try:
                rls_match = _euler_re.match(rls).groups()
                if rls_match[0]:
                    os = "euleros_v" + rls_match[0]
                if rls_match[2]:
                    os = os + rls_match[2].lower()
                else:
                    os = os + rls_match + "sp0"
                if rls_match[3]:
                    os = os + "(" + rls_match[3] + ")"
            except ValueError:
                os = None
            except IndexError:
                logger.warning(
                    "Regular Expression %s might be incorrect",
                    _euler_re.pattern,
                )

            # Euler OS Virtualization ...
            try:
                rls = EulerOS.command(ssh, "cat /etc/uvp-release")
                if rls.find("EulerOS Virtualization") >= 0:
                    rls_match = _euler_v_re.match(rls).groups()
                    if rls_match[0]:
                        os = "euleros_virtualization_"
                        if rls_match[0].find("for ARM 64") >= 0:
                            os = os + "for_arm_64_"
                        if rls_match[1]:
                            os = os + rls_match[1]
            except ValueError:
                os = None
            except IndexError:
                logger.warning(
                    "Regular Expression %s might be incorrect",
                    _euler_re.pattern,
                )

        return os

    @staticmethod
    def gather_package_list(ssh: SSHClient) -> List[str]:
        packages_str = EulerOS.command(
            ssh, "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'"
        )
        packages = packages_str.strip().splitlines()
        return packages
