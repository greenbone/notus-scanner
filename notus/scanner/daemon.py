# Copyright (C) 2014-2021 Greenbone Networks GmbH
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

import logging
import sys

from pathlib import Path

from .cli import create_parser
from .loader import JSONAdvisoriesLoader
from .messaging.mqtt import (
    MQTTDaemon,
    MQTTPublisher,
    MQTTClient,
    MQTTSubscriber,
)
from .messages.start import ScanStartMessage
from .scanner import NotusScanner
from .utils import (
    go_to_background,
    create_pid,
    init_signal_handler,
    init_logging,
)

from .__version__ import __version__

logger = logging.getLogger(__name__)


def run_daemon(
    mqtt_broker_address: str,
    mqtt_broker_port: int,
    advisories_directory_path: Path,
):
    """Initialize the mqtt client, mqtt handler, notus scanner and run
    forever
    """
    loader = JSONAdvisoriesLoader(
        advisories_directory_path=advisories_directory_path
    )
    try:
        client = MQTTClient(
            mqtt_broker_address=mqtt_broker_address,
            mqtt_broker_port=mqtt_broker_port,
        )
    except ConnectionRefusedError:
        logger.error(
            'Could not connect to MQTT broker at %s. Connection refused.',
            mqtt_broker_address,
        )
        sys.exit(1)

    daemon = MQTTDaemon(client)

    publisher = MQTTPublisher(client)
    scanner = NotusScanner(loader=loader, publisher=publisher)

    subscriber = MQTTSubscriber(client)
    subscriber.subscribe(ScanStartMessage, scanner.run_scan)

    daemon.run()


def main():
    parser = create_parser("Notus Scanner")
    args = parser.parse_arguments()

    if args.version:
        print(f'Notus Scanner {__version__}')
        sys.exit()

    init_logging(
        "notus-scanner",
        args.log_level,
        log_file=args.log_file,
        foreground=args.foreground,
    )

    if not args.foreground:
        go_to_background()

    if not create_pid(args.pid_file):
        sys.exit()

    init_signal_handler(args.pid_file)

    logger.info("Starting notus-scanner version %s.", __version__)

    run_daemon(
        args.mqtt_broker_address,
        args.mqtt_broker_port,
        args.advisories_directory,
    )


if __name__ == "__main__":
    main()
