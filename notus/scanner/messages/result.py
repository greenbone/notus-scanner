# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional, Union
from uuid import UUID

from ..errors import MessageParsingError
from .message import Message, MessageType


class ResultType(Enum):
    ALARM = "ALARM"


class ResultMessage(Message):
    message_type: MessageType = MessageType.RESULT
    topic = "scanner/scan/info"

    def __init__(
        self,
        *,
        scan_id: str,
        host_ip: str,
        host_name: str,
        oid: str,
        value: str,
        port: str = "package",
        uri: str = "",
        result_type: ResultType = ResultType.ALARM,
        message_id: Optional[UUID] = None,
        group_id: Optional[UUID] = None,
        created: Optional[datetime] = None,
    ):
        super().__init__(
            message_id=message_id, group_id=group_id, created=created
        )
        self.scan_id = scan_id
        self.host_ip = host_ip
        self.host_name = host_name
        self.oid = oid
        self.value = value
        self.port = port
        self.uri = uri
        self.result_type = result_type

    def serialize(self) -> Dict[str, Union[int, str]]:
        message = super().serialize()
        message.update(
            {
                "scan_id": self.scan_id,
                "host_ip": self.host_ip,
                "host_name": self.host_name,
                "oid": self.oid,
                "value": self.value,
                "port": self.port,
                "uri": self.uri,
                "result_type": self.result_type.value,
            }
        )
        return message

    @classmethod
    def _parse(cls, data: Dict[str, Union[int, str]]) -> Dict[str, Any]:
        kwargs = super()._parse(data)
        try:
            kwargs.update(
                {
                    "scan_id": data.get("scan_id"),
                    "host_ip": data.get("host_ip"),
                    "host_name": data.get("host_name"),
                    "oid": data.get("oid"),
                    "value": data.get("value"),
                    "port": data.get("port"),
                    "uri": data.get("uri"),
                    "result_type": ResultType(data.get("result_type")),
                }
            )
        except ValueError as e:
            raise MessageParsingError(
                f"error while parsing 'result_type', {e}"
            ) from e
        return kwargs
