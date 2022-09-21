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
import logging
from pathlib import Path
from uuid import uuid4

from ..cli.parser import log_level
from ..config import DEFAULT_MQTT_BROKER_ADDRESS, DEFAULT_MQTT_BROKER_PORT
from ..messages.start import ScanStartMessage
from ..messaging.mqtt import MQTTClient, MQTTPublisher


def after_publish(client, _userdata, _mid):
    client.disconnect()


def main():
    parser = argparse.ArgumentParser(
        description="A test client to start generating scan results via the "
        "Notus Scanner"
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
        "-s",
        "--scan-id",
        help="ID to use for the scan. If no scan ID is provided a random ID "
        "will be generated",
    )
    parser.add_argument(
        "--host-ip",
        required=True,
        help="IP address of the host to report in generated results",
    )
    parser.add_argument(
        "--host-name", help="Name of the host to report in generated results"
    )
    parser.add_argument(
        "--os-release",
        required=True,
        help="Name of the Operating System Release to scan",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--packages",
        nargs="+",
        help="List of packages to compare for vulnerabilities",
    )
    group.add_argument(
        "--package-file",
        type=Path,
        help="Path to a file containing a list of packages to compare for "
        "vulnerabilities",
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

    scan_id = args.scan_id or str(uuid4())
    if args.packages:
        package_list = args.packages
    else:
        package_file_path: Path = args.package_file
        with package_file_path.open("r", encoding="utf-8") as f:
            package_list = f.readlines()

    print(f"Starting a scan with ID {scan_id}")

    start_scan_message = ScanStartMessage(
        scan_id=scan_id,
        host_ip=args.host_ip,
        host_name=args.host_name,
        os_release=args.os_release,
        package_list=package_list,
    )
    client = MQTTClient(
        mqtt_broker_address=args.mqtt_broker_address,
        mqtt_broker_port=args.mqtt_broker_port,
        client_id=f"notus-scan-start-{scan_id}",
    )
    client.on_publish = after_publish
    client.connect()
    client.loop()

    publisher = MQTTPublisher(client)
    publisher.publish(start_scan_message)

    client.loop_forever()


if __name__ == "__main__":
    main()
