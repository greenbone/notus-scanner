# Copyright (C) 2021 Greenbone Networks GmbH
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

import json
import logging

from functools import partial
from typing import Callable, List

import paho.mqtt.client as mqtt

from ..messages.message import Message
from ..messages.start import ScanStartMessage

logger = logging.getLogger(__name__)

NOTUS_MQTT_CLIENT_ID = "notus-scanner"

QOS_AT_LEAST_ONCE = 1

ScanFunction = Callable[
    [
        str,  # scan_id
        str,  # host_ip
        str,  # host_name
        str,  # os_release
        List[str],  # package_list
    ],
    None,
]


class MQTTClient(mqtt.Client):
    def __init__(
        self, mqtt_broker_address: str, client_id=NOTUS_MQTT_CLIENT_ID
    ):
        super().__init__(client_id=client_id, protocol=mqtt.MQTTv5)
        self.connect(mqtt_broker_address)


class MQTTPublisher:
    def __init__(self, client: MQTTClient):
        self._client = client

    def publish(self, message: Message) -> None:
        logger.debug('Publish message %s', message)
        self._client.publish(message.topic, str(message), qos=QOS_AT_LEAST_ONCE)


class MQTTHandler:
    """MQTT Handler for notus scanner related messages."""

    def __init__(
        self,
        client: MQTTClient,
        start_scan_function: ScanFunction,
    ):
        self._client = client

        self._client.on_publish = self.on_publish
        self._client.on_disconnect = self.on_disconnect
        self._client.on_connect = self.on_connect

        logger.debug("Subscribing to topic %s", ScanStartMessage.topic)

        self._client.message_callback_add(
            ScanStartMessage.topic,
            partial(self._handle_start_scan, start_scan_function),
        )

        client.loop_forever()

    @staticmethod
    def on_connect(_client, _userdata, _flags, rc, _properties):
        if rc == 0:
            logger.debug("Connected to broker %s successfully")
        else:
            logger.error('Failed to connect to broker. Reason Code %s', rc)

    @staticmethod
    def on_publish(_client, _userdata, mid):  # pylint: disable=unused-argument
        logger.debug("Message with mid value %d has been published", mid)

    @staticmethod
    def on_disconnect(client, _userdata, rc=0):
        logger.info("Disconnected result code %s", rc)
        client.loop_stop()

    @staticmethod
    def _handle_start_scan(
        start_scan_function: ScanFunction,
        _client,
        _userdata,
        msg: mqtt.MQTTMessage,
    ):
        logger.debug("Got MQTT start scan message")

        try:
            # Load start_data as dictionary
            message = ScanStartMessage.load(msg.payload)
        except json.JSONDecodeError:
            logger.error("Got MQTT message in non-json format.")
            logger.debug("Got: %s", msg.payload)
            return
        except ValueError as e:
            logger.error("Could not parse start scan message %s", e)
            logger.debug("Got: %s", msg.payload)
            return

        start_scan_function(
            message.scan_id,
            message.host_ip,
            message.host_name,
            message.os_release,
            message.package_list,
        )
