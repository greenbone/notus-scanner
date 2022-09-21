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

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from ..errors import MessageParsingError
from .message import Message, MessageType


class ScanStartMessage(Message):
    message_type: MessageType = MessageType.SCAN_START
    topic = "scanner/package/cmd/notus"

    scan_id: str
    host_ip: str
    host_name: str
    os_release: str
    package_list: List[str]

    def __init__(
        self,
        *,
        scan_id: str,
        host_ip: str,
        host_name: str,
        os_release: str,
        package_list: List[str],
        message_id: Optional[UUID] = None,
        group_id: Optional[str] = None,
        created: Optional[datetime] = None,
    ):
        super().__init__(
            message_id=message_id, group_id=group_id, created=created
        )
        self.scan_id = scan_id
        self.host_ip = host_ip
        self.host_name = host_name
        self.os_release = os_release
        self.package_list = package_list if package_list is not None else []

    def serialize(self) -> Dict[str, Union[int, str, List[str]]]:
        message = super().serialize()
        message.update(
            {
                "scan_id": self.scan_id,
                "host_ip": self.host_ip,
                "host_name": self.host_name,
                "os_release": self.os_release,
                "package_list": self.package_list,
            }
        )
        return message

    @classmethod
    def _parse(cls, data: Dict[str, Union[int, str]]) -> Dict[str, Any]:
        kwargs = super()._parse(data)

        package_list = data.get("package_list")
        if not isinstance(package_list, list):
            raise MessageParsingError("package_list must contain a list")

        kwargs.update(
            {
                "scan_id": data.get("scan_id"),
                "host_ip": data.get("host_ip"),
                "host_name": data.get("host_name"),
                "os_release": data.get("os_release"),
                "package_list": package_list,
            }
        )
        return kwargs
