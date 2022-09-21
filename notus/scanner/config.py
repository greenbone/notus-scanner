# Copyright (C) 2020-2022 Greenbone Networks GmbH
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

"""
Module to store Notus Scanner configuration settings
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict

import tomli

from notus.scanner.errors import ConfigFileError

logger = logging.getLogger(__name__)

DEFAULT_PRODUCTS_DIRECTORY = "/var/lib/openvas/plugins/notus/products"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_MQTT_BROKER_ADDRESS = "localhost"
DEFAULT_MQTT_BROKER_PORT = 1883
DEFAULT_PID_FILE = "/run/notus-scanner/notus-scanner.pid"

_CONFIG = (
    (
        "products-directory",
        "NOTUS_SCANNER_PRODUCTS_DIRECTORY",
        DEFAULT_PRODUCTS_DIRECTORY,
    ),
    ("log-file", "NOTUS_SCANNER_LOG_FILE", None),
    ("log-level", "NOTUS_SCANNER_LOG_LEVEL", DEFAULT_LOG_LEVEL),
    (
        "mqtt-broker-address",
        "NOTUS_SCANNER_MQTT_BROKER_ADDRESS",
        DEFAULT_MQTT_BROKER_ADDRESS,
    ),
    (
        "mqtt-broker-port",
        "NOTUS_SCANNER_MQTT_BROKER_PORT",
        DEFAULT_MQTT_BROKER_PORT,
    ),
    ("pid-file", "NOTUS_SCANNER_PID_FILE", DEFAULT_PID_FILE),
    (
        "disable-hashsum-verification",
        "NOTUS_DISABLE_HASHSUM_VERIFICATION",
        False,
    ),
)


class Config:
    def __init__(self) -> None:
        self._config: Dict[str, Any] = {}

    def load(self, filepath: Path) -> None:
        try:
            content = filepath.read_text(encoding="utf-8")
            config_data = tomli.loads(content)
        except IOError as e:
            raise ConfigFileError(
                f"Can't load config file {filepath.absolute()}. Error was {e}."
            ) from e
        except tomli.TOMLDecodeError as e:
            raise ConfigFileError(
                f"Can't load config file. {filepath.absolute()} is not a valid "
                "TOML file."
            ) from e

        self._config = config_data.get("notus-scanner", {})

    def values(self) -> Dict[str, Any]:
        values = {}

        for config_key, env_key, default in _CONFIG:
            if env_key in os.environ:
                values[config_key] = os.environ.get(env_key)
            elif config_key in self._config:
                values[config_key] = self._config.get(config_key)
            else:
                values[config_key] = default

        return values
