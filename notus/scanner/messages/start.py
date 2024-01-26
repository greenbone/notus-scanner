# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

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
