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
from typing import Optional
from paramiko import SSHClient

from .distribution import Distribution

logger = logging.getLogger(__name__)


_debian_re = re.compile(r"^([0-9]+)([0-9.]+)")


class Debian(Distribution):
    @staticmethod
    def get_os(ssh: SSHClient) -> Optional[str]:
        # Try Debian
        rls = Debian.command(ssh, "cat /etc/debian_version")
        if (
            _debian_re.match(rls)
            or rls.find("buster/sid") >= 0
            or rls.find("bullseye/sid") >= 0
        ):
            # It still can be Ubuntu
            if Debian.command(ssh, "cat /etc/lsb-release"):
                return
            # It is Debian
            os = "debian_"
            # Getting Version
            try:
                versions = _debian_re.match(rls).groups()
                v1 = int(versions[0])
                if v1 <= 3:  # version 3 needs the minor version as well
                    os = os + versions[0] + versions[1]
                else:  # versions grater than 3 only needs the major version
                    os = os + versions[0]
                return os
            except (AttributeError, ValueError):
                logger.debug("Not supported Debian Version: %s", rls)
            except IndexError:
                logger.warning(
                    "Regular Expression %s might be incorrect",
                    _debian_re.pattern,
                )

    @staticmethod
    def gather_package_list(ssh: SSHClient) -> list[str]:
        packages_str = Debian.command(
            ssh, r"dpkg-query -W -f=\$\{Package\}-\$\{Version\}'\n'"
        )
        packages = packages_str.strip().splitlines()
        return packages
