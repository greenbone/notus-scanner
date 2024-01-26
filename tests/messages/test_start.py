# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime, timezone
from unittest import TestCase
from uuid import UUID

from notus.scanner.errors import MessageParsingError
from notus.scanner.messages.message import MessageType
from notus.scanner.messages.start import ScanStartMessage


class ScanStartMessageTestCase(TestCase):
    def test_constructor(self):
        message = ScanStartMessage(
            scan_id="scan_1",
            host_ip="1.1.1.1",
            host_name="foo",
            os_release="BarOS 1.0",
            package_list=["foo-1.2.3-1.x86_64"],
        )

        self.assertIsInstance(message.message_id, UUID)
        self.assertIsInstance(message.group_id, str)
        self.assertIsInstance(message.created, datetime)

        self.assertEqual(message.message_type, MessageType.SCAN_START)
        self.assertEqual(message.topic, "scanner/package/cmd/notus")

        self.assertEqual(message.scan_id, "scan_1")
        self.assertEqual(message.host_ip, "1.1.1.1")
        self.assertEqual(message.host_name, "foo")
        self.assertEqual(message.os_release, "BarOS 1.0")
        self.assertEqual(message.package_list, ["foo-1.2.3-1.x86_64"])

    def test_serialize(self):
        created = datetime.fromtimestamp(1628512774)
        message_id = UUID("63026767-029d-417e-9148-77f4da49f49a")
        group_id = "866350e8-1492-497e-b12b-c079287d51dd"
        message = ScanStartMessage(
            message_id=message_id,
            group_id=group_id,
            created=created,
            scan_id="scan_1",
            host_ip="1.1.1.1",
            host_name="foo",
            os_release="BarOS 1.0",
            package_list=["foo-1.2.3-1.x86_64"],
        )

        serialized = message.serialize()
        self.assertEqual(serialized["created"], 1628512774.0)
        self.assertEqual(
            serialized["message_id"], "63026767-029d-417e-9148-77f4da49f49a"
        )
        self.assertEqual(
            serialized["group_id"], "866350e8-1492-497e-b12b-c079287d51dd"
        )
        self.assertEqual(serialized["message_type"], "scan.start")
        self.assertEqual(serialized["scan_id"], "scan_1")
        self.assertEqual(serialized["host_ip"], "1.1.1.1")
        self.assertEqual(serialized["host_name"], "foo")
        self.assertEqual(serialized["os_release"], "BarOS 1.0")
        self.assertEqual(serialized["package_list"], ["foo-1.2.3-1.x86_64"])

    def test_deserialize(self):
        data = {
            "message_id": "63026767-029d-417e-9148-77f4da49f49a",
            "group_id": "866350e8-1492-497e-b12b-c079287d51dd",
            "created": 1628512774.0,
            "message_type": "scan.start",
            "scan_id": "scan_1",
            "host_ip": "1.1.1.1",
            "host_name": "foo",
            "os_release": "BarOS 1.0",
            "package_list": ["foo-1.2.3-1.x86_64"],
        }

        message = ScanStartMessage.deserialize(data)
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
        self.assertEqual(message.message_type, MessageType.SCAN_START)

        self.assertEqual(message.scan_id, "scan_1")
        self.assertEqual(message.host_ip, "1.1.1.1")
        self.assertEqual(message.host_name, "foo")
        self.assertEqual(message.os_release, "BarOS 1.0")
        self.assertEqual(message.package_list, ["foo-1.2.3-1.x86_64"])

        self.assertEqual(message.topic, "scanner/package/cmd/notus")

    def test_deserialize_invalid_message_type(self):
        data = {
            "message_id": "63026767-029d-417e-9148-77f4da49f49a",
            "group_id": "866350e8-1492-497e-b12b-c079287d51dd",
            "created": 1628512774.0,
            "message_type": "scan.status",
            "scan_id": "scan_1",
            "host_ip": "1.1.1.1",
            "host_name": "foo",
            "os_release": "BarOS 1.0",
            "package_list": ["foo-1.2.3-1.x86_64"],
        }

        with self.assertRaisesRegex(
            MessageParsingError,
            "Invalid message type MessageType.SCAN_STATUS for ScanStartMessage."
            " Must be MessageType.SCAN_START.",
        ):
            ScanStartMessage.deserialize(data)

    def test_deserialize_invalid_package_list(self):
        data = {
            "message_id": "63026767-029d-417e-9148-77f4da49f49a",
            "group_id": "866350e8-1492-497e-b12b-c079287d51dd",
            "created": "1628512774.0",
            "message_type": "scan.start",
            "scan_id": "scan_1",
            "host_ip": "1.1.1.1",
            "host_name": "foo",
            "os_release": "BarOS 1.0",
            "package_list": "foo-1.2.3-1.x86_64",
        }

        with self.assertRaisesRegex(
            MessageParsingError, "package_list must contain a list"
        ):
            ScanStartMessage.deserialize(data)
