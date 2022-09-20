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

from datetime import datetime, timezone
from unittest import TestCase
from uuid import UUID

from notus.scanner.errors import MessageParsingError
from notus.scanner.messages.message import MessageType
from notus.scanner.messages.status import ScanStatus, ScanStatusMessage


class ScanStatusMessageTestCase(TestCase):
    def test_constructor(self):
        message = ScanStatusMessage(
            scan_id="scan_1", host_ip="1.1.1.1", status=ScanStatus.FINISHED
        )

        self.assertIsInstance(message.message_id, UUID)
        self.assertIsInstance(message.group_id, str)
        self.assertIsInstance(message.created, datetime)

        self.assertEqual(message.message_type, MessageType.SCAN_STATUS)
        self.assertEqual(message.topic, "scanner/status")

        self.assertEqual(message.scan_id, "scan_1")
        self.assertEqual(message.host_ip, "1.1.1.1")
        self.assertEqual(message.status, ScanStatus.FINISHED)

    def test_serialize(self):
        created = datetime.fromtimestamp(1628512774)
        message_id = UUID("63026767-029d-417e-9148-77f4da49f49a")
        group_id = UUID("866350e8-1492-497e-b12b-c079287d51dd")
        message = ScanStatusMessage(
            message_id=message_id,
            group_id=group_id,
            created=created,
            scan_id="scan_1",
            host_ip="1.1.1.1",
            status=ScanStatus.FINISHED,
        )

        serialized = message.serialize()
        self.assertEqual(serialized["created"], 1628512774.0)
        self.assertEqual(
            serialized["message_id"], "63026767-029d-417e-9148-77f4da49f49a"
        )
        self.assertEqual(
            serialized["group_id"], "866350e8-1492-497e-b12b-c079287d51dd"
        )
        self.assertEqual(serialized["message_type"], "scan.status")
        self.assertEqual(serialized["scan_id"], "scan_1")
        self.assertEqual(serialized["host_ip"], "1.1.1.1")
        self.assertEqual(serialized["status"], "finished")

    def test_deserialize(self):
        data = {
            "message_id": "63026767-029d-417e-9148-77f4da49f49a",
            "group_id": "866350e8-1492-497e-b12b-c079287d51dd",
            "created": 1628512774.0,
            "message_type": "scan.status",
            "scan_id": "scan_1",
            "host_ip": "1.1.1.1",
            "status": "finished",
        }

        message = ScanStatusMessage.deserialize(data)
        self.assertEqual(
            message.message_id, UUID("63026767-029d-417e-9148-77f4da49f49a")
        )
        self.assertEqual(
            message.group_id, "866350e8-1492-497e-b12b-c079287d51dd"
        )
        self.assertEqual(
            message.created,
            datetime.fromtimestamp(1628512774.0, tz=timezone.utc),
        )
        self.assertEqual(message.message_type, MessageType.SCAN_STATUS)

        self.assertEqual(message.scan_id, "scan_1")
        self.assertEqual(message.host_ip, "1.1.1.1")
        self.assertEqual(message.status, ScanStatus.FINISHED)
        self.assertEqual(message.topic, "scanner/status")

    def test_deserialize_invalid_status(self):
        data = {
            "message_id": "63026767-029d-417e-9148-77f4da49f49a",
            "group_id": "866350e8-1492-497e-b12b-c079287d51dd",
            "created": 1628512774.0,
            "message_type": "scan.status",
            "scan_id": "scan_1",
            "host_ip": "1.1.1.1",
            "status": "foo",
        }

        with self.assertRaisesRegex(
            ValueError, "'foo' is not a valid ScanStatus"
        ):
            ScanStatusMessage.deserialize(data)

    def test_deserialize_invalid_message_type(self):
        data = {
            "message_id": "63026767-029d-417e-9148-77f4da49f49a",
            "group_id": "866350e8-1492-497e-b12b-c079287d51dd",
            "created": 1628512774.0,
            "message_type": "scan.start",
            "scan_id": "scan_1",
            "host_ip": "1.1.1.1",
            "status": "foo",
        }

        with self.assertRaisesRegex(
            MessageParsingError,
            "Invalid message type MessageType.SCAN_START for ScanStatusMessage."
            " Must be MessageType.SCAN_STATUS.",
        ):
            ScanStatusMessage.deserialize(data)
