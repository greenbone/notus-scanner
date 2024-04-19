# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import logging
from functools import partial
from typing import Callable, Type

import paho.mqtt.client as mqtt
from paho.mqtt import __version__ as paho_mqtt_version

from ..errors import MessageParsingError
from ..messages.message import Message
from .publisher import Publisher
from .subscriber import Subscriber

logger = logging.getLogger(__name__)

NOTUS_MQTT_CLIENT_ID = "notus-scanner"

QOS_AT_LEAST_ONCE = 1


def is_paho_mqtt_version_2() -> bool:
    return paho_mqtt_version.startswith("2")


class MQTTClient(mqtt.Client):
    def __init__(
        self,
        mqtt_broker_address: str,
        mqtt_broker_port: int,
        client_id=NOTUS_MQTT_CLIENT_ID,
    ):
        self._mqtt_broker_address = mqtt_broker_address
        self._mqtt_broker_port = mqtt_broker_port

        mqtt_client_args = {
            "client_id": client_id,
            "protocol": mqtt.MQTTv5,
        }

        if is_paho_mqtt_version_2():
            logger.debug("Using Paho MQTT version 2")
            mqtt_client_args["callback_api_version"] = (
                mqtt.CallbackAPIVersion.VERSION1
            )
        else:
            logger.debug("Using Paho MQTT version 1")

        super().__init__(**mqtt_client_args)

        self.enable_logger()

    def connect(
        self,
        host=None,
        port=None,
        keepalive=60,
        bind_address="",
        bind_port=0,
        clean_start=mqtt.MQTT_CLEAN_START_FIRST_ONLY,
        properties=None,
    ):
        if not host:
            host = self._mqtt_broker_address
        if not port:
            port = self._mqtt_broker_port

        return super().connect(
            host,
            port=port,
            keepalive=keepalive,
            bind_address=bind_address,
            bind_port=bind_port,
            clean_start=clean_start,
            properties=properties,
        )


class MQTTPublisher(Publisher):
    def __init__(self, client: MQTTClient):
        self._client = client

    def publish(self, message: Message) -> None:
        logger.debug("Publish message %s", message)
        self._client.publish(message.topic, str(message), qos=QOS_AT_LEAST_ONCE)


class MQTTSubscriber(Subscriber):
    def __init__(self, client: MQTTClient):
        self._client = client
        # Save the active subscriptions on subscribe() so we can resubscribe
        # after reconnect
        self._subscriptions: dict = {}

        self._client.on_connect = self.on_connect
        self._client.user_data_set(self._subscriptions)

    def subscribe(
        self, message_class: Type[Message], callback: Callable[[Message], None]
    ) -> None:
        func = partial(self._handle_message, message_class, callback)
        func.__name__ = callback.__name__

        logger.debug("Subscribing to topic %s", message_class.topic)

        self._client.subscribe(message_class.topic, qos=QOS_AT_LEAST_ONCE)
        self._client.message_callback_add(message_class.topic, func)

        self._subscriptions[message_class.topic] = func

    @staticmethod
    def on_connect(_client, _userdata, _flags, rc, _properties):
        if rc == 0:
            # If we previously had active subscription we subscribe to them
            # again because they got lost after a broker disconnect.
            # Userdata was set in __init__()
            if _userdata:
                for topic, func in _userdata.items():
                    _client.subscribe(topic, qos=QOS_AT_LEAST_ONCE)
                    _client.message_callback_add(topic, func)

    @staticmethod
    def _handle_message(
        message_class: Type[Message],
        callback: Callable[[Message], None],
        _client,
        _userdata,
        msg: mqtt.MQTTMessage,
    ) -> None:
        logger.debug("Incoming message for topic %s", msg.topic)

        try:
            # Load message from payload
            message = message_class.load(msg.payload)
        except json.JSONDecodeError:
            logger.error(
                "Got MQTT message in non-json format for topic %s.", msg.topic
            )
            logger.debug("Got: %s", msg.payload)
            return
        except MessageParsingError as e:
            logger.error(
                "Could not parse message for topic %s. Error was %s",
                msg.topic,
                e,
            )
            logger.debug("Got: %s", msg.payload)
            return

        callback(message)


class MQTTDaemon:
    """A class to start and stop the MQTT client"""

    def __init__(
        self,
        client: MQTTClient,
    ):
        self._client = client

        self._client.connect()

    def run(self):
        self._client.loop_forever()
