# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Module to store Notus Scanner configuration settings
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict

from notus.scanner.errors import ConfigFileError

if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import tomli as toml

logger = logging.getLogger(__name__)

DEFAULT_PRODUCTS_DIRECTORY = "/var/lib/notus/products"
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
        "mqtt-broker-username",
        "NOTUS_SCANNER_MQTT_BROKER_USERNAME",
        None,
    ),
    (
        "mqtt-broker-password",
        "NOTUS_SCANNER_MQTT_BROKER_PASSWORD",
        None,
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
            config_data = toml.loads(content)
        except IOError as e:
            raise ConfigFileError(
                f"Can't load config file {filepath.absolute()}. Error was {e}."
            ) from e
        except toml.TOMLDecodeError as e:
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
