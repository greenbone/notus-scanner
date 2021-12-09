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
import os
import sys

from pathlib import Path
from typing import Dict, Optional

from .cli import create_parser
from .errors import Sha256SumLoadingError
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

from .loader.gpg_sha_verifier import (
    ReloadConfiguration,
    create_verify,
    reload_sha256sums,
)

from .__version__ import __version__


logger = logging.getLogger(__name__)

SENTRY_DSN_NOTUS_SCANNER = os.environ.get("SENTRY_DSN_NOTUS_SCANNER")
if SENTRY_DSN_NOTUS_SCANNER:
    import sentry_sdk  # pylint: disable=import-error

    sentry_sdk.init(  # pylint: disable=abstract-class-instantiated
        SENTRY_DSN_NOTUS_SCANNER,
        traces_sample_rate=1.0,
        server_name=os.environ.get("SENTRY_SERVER_NAME"),
        environment=os.environ.get("SENTRY_ENVIRONMENT"),
    )


def run_daemon(
    mqtt_broker_address: str,
    mqtt_broker_port: int,
    advisories_directory_path: Path,
):
    """Initialize the mqtt client, mqtt handler, notus scanner and run
    forever
    """

    def on_hash_sum_verification_failure(
        _: Optional[Dict[str, str]]
    ) -> Dict[str, str]:
        raise Sha256SumLoadingError(
            f"Unable to verify signature of {sha_sum_file_path}"
        )

    sha_sum_file_path = advisories_directory_path / "sha256sums"
    sha_sum_reload_config = ReloadConfiguration(
        hash_file=sha_sum_file_path,
        on_verification_failure=on_hash_sum_verification_failure,
    )

    sums = reload_sha256sums(sha_sum_reload_config)
    verifier = create_verify(sums)

    loader = JSONAdvisoriesLoader(
        advisories_directory_path=advisories_directory_path, verify=verifier
    )
    try:
        client = MQTTClient(
            mqtt_broker_address=mqtt_broker_address,
            mqtt_broker_port=mqtt_broker_port,
        )
    except ConnectionRefusedError:
        logger.error(
            "Could not connect to MQTT broker at %s. Connection refused.",
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
