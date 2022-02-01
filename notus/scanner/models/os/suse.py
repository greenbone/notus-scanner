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

import re
from typing import Optional
from paramiko import SSHClient
from .distribution import Distribution

_suse_re = re.compile(r"(open)?suse( leap| linux)?([a-zA-Z0-9 ]+)")


class SuSE(Distribution):
    @staticmethod
    def get_os(ssh: SSHClient) -> Optional[str]:
        # Try SuSE
        os = None
        rls = SuSE.command(ssh, "cat /etc/os-release")
        if not rls:
            rls = SuSE.command(ssh, "cat /usr/lib/os-release")

        if _suse_re.match(rls) and rls.find("enterprise") == -1:
            if rls.find("opensuse leap"):
                os = "opensuseleap"
            elif rls.find("opensuse"):
                os = "opensuse"
            else:
                os = "suse"
            # Other SuSE Versions?

        return os

    @staticmethod
    def gather_package_list(ssh: SSHClient) -> list[str]:
        packages_str = SuSE.command(
            ssh, "/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'"
        )
        packages = packages_str.strip().splitlines()
        return packages
