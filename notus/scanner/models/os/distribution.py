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

from typing import Optional
from paramiko import SSHClient


class Distribution:
    """Distribution is the Base Class for all Distributions supported by the
    notus scanner. I contains methods to optain the corresponding distribution
    release with version and the package list."""

    @staticmethod
    def get_os(ssh: SSHClient) -> Optional[str]:
        """Get the operating system, if the ssh client is connected to the
        coresponding distribution"""
        raise NotImplementedError

    @staticmethod
    def gather_package_list(ssh: SSHClient) -> list[str]:
        """Get the package list of the system, the ssh client is connected to.
        The ssh client must be connected to the corresponding distribution"""
        raise NotImplementedError

    @staticmethod
    def command(ssh: SSHClient, command: str) -> str:
        """Executes a given command via a given ssh connection and returns the
        stdout as a string"""
        _, ssh_stdout, _ = ssh.exec_command(command)
        return ssh_stdout.read().decode("utf-8")
