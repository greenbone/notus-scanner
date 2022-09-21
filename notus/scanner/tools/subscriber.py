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

import argparse
import atexit
import logging
import signal
from functools import partial

from ..cli.parser import log_level
from ..config import DEFAULT_MQTT_BROKER_ADDRESS, DEFAULT_MQTT_BROKER_PORT
from ..messages.result import ResultMessage
from ..messages.status import ScanStatusMessage
from ..messaging.mqtt import MQTTClient, MQTTSubscriber


def print_scan_status(message: ScanStatusMessage):
    print("Scan Status")
    print("-----------")
    print(message.status)
    print("-----------\n")


def print_result_message(message: ResultMessage):
    print("Scan Result")
    print("-----------")
    print(f"OID {message.oid}")
    print(f"Host {message.host_ip} {message.host_name or ''}")
    print(message.value)
    print("-----------\n")


def disconnect(
    client: MQTTClient,
    _signum=None,
    _frame=None,
) -> None:
    client.disconnect()


def main():
    parser = argparse.ArgumentParser(
        description="A test client to show messages created by the Notus "
        "Scanner"
    )
    parser.add_argument(
        "-b",
        "--mqtt-broker-address",
        type=str,
        required=True,
        default=DEFAULT_MQTT_BROKER_ADDRESS,
        help="Hostname or IP address of the MQTT broker.",
    )
    parser.add_argument(
        "-p",
        "--mqtt-broker-port",
        type=int,
        default=DEFAULT_MQTT_BROKER_PORT,
        help="Port of the MQTT broker. (default: %(default)s)",
    )
    parser.add_argument(
        "-L",
        "--log-level",
        default="INFO",
        type=log_level,
        help="Wished level of logging (default: %(default)s)",
    )

    args = parser.parse_args()

    logging.basicConfig(level=args.log_level)

    client = MQTTClient(
        mqtt_broker_address=args.mqtt_broker_address,
        mqtt_broker_port=args.mqtt_broker_port,
        client_id="notus-subscriber",
    )
    client.connect()

    subscriber = MQTTSubscriber(client)
    subscriber.subscribe(ScanStatusMessage, print_scan_status)
    subscriber.subscribe(ResultMessage, print_result_message)

    disconnect_func = partial(disconnect, client)

    atexit.register(disconnect_func, client)
    signal.signal(signal.SIGTERM, disconnect_func)
    signal.signal(signal.SIGINT, disconnect_func)

    client.loop_forever()


if __name__ == "__main__":
    main()
