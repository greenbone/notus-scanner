# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from datetime import datetime
from unittest import TestCase, mock
from uuid import UUID

from notus.scanner.messages.start import ScanStartMessage
from notus.scanner.messaging.mqtt import (
    MQTTDaemon,
    MQTTPublisher,
    MQTTSubscriber,
)


class MQTTPublisherTestCase(TestCase):
    def test_publish(self):
        client = mock.MagicMock()
        publisher = MQTTPublisher(client)

        created = datetime.fromtimestamp(1628512774)
        message_id = UUID("63026767-029d-417e-9148-77f4da49f49a")
        group_id = UUID("866350e8-1492-497e-b12b-c079287d51dd")
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

        publisher.publish(message)

        client.publish.assert_called_with(
            "scanner/package/cmd/notus",
            '{"message_id": "63026767-029d-417e-9148-77f4da49f49a", '
            '"message_type": "scan.start", '
            '"group_id": "866350e8-1492-497e-b12b-c079287d51dd", '
            '"created": 1628512774.0, '
            '"scan_id": "scan_1", '
            '"host_ip": "1.1.1.1", '
            '"host_name": "foo", '
            '"os_release": "BarOS 1.0", '
            '"package_list": ["foo-1.2.3-1.x86_64"]}',
            qos=1,
        )


class MQTTSubscriberTestCase(TestCase):
    def test_subscribe(self):
        client = mock.MagicMock()
        callback = mock.MagicMock()
        callback.__name__ = "callback_name"

        subscriber = MQTTSubscriber(client)

        subscriber.subscribe(ScanStartMessage, callback)

        client.subscribe.assert_called_with("scanner/package/cmd/notus", qos=1)


class MQTTDaemonTestCase(TestCase):
    def test_connect(self):
        client = mock.MagicMock()

        # pylint: disable=unused-variable
        daemon = MQTTDaemon(client)  # noqa: F841

        client.connect.assert_called_with()

    def test_run(self):
        client = mock.MagicMock()

        daemon = MQTTDaemon(client)

        daemon.run()

        client.loop_forever.assert_called_with()
