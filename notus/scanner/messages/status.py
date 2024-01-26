# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional, Union
from uuid import UUID

from .message import Message, MessageType


class ScanStatus(Enum):
    FINISHED = "finished"
    REQUESTED = "requested"
    QUEUED = "queued"
    INIT = "init"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    INTERRUPTED = "interrupted"


class ScanStatusMessage(Message):
    message_type = MessageType.SCAN_STATUS
    topic = "scanner/status"

    def __init__(
        self,
        *,
        scan_id: str,
        host_ip: str,
        status: ScanStatus,
        message_id: Optional[UUID] = None,
        group_id: Optional[str] = None,
        created: Optional[datetime] = None,
    ):
        super().__init__(
            message_id=message_id, group_id=group_id, created=created
        )
        self.scan_id = scan_id
        self.host_ip = host_ip
        self.status = status

    def serialize(self) -> Dict[str, Union[int, str]]:
        message = super().serialize()
        message.update(
            {
                "scan_id": self.scan_id,
                "host_ip": self.host_ip,
                "status": self.status.value,
            }
        )
        return message

    @classmethod
    def _parse(cls, data: Dict[str, Union[int, str]]) -> Dict[str, Any]:
        kwargs = super()._parse(data)
        kwargs.update(
            {
                "scan_id": data.get("scan_id"),
                "host_ip": data.get("host_ip"),
                "status": ScanStatus(data.get("status")),
            }
        )
        return kwargs
