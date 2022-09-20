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

import unittest
from unittest.mock import patch

from notus.scanner.config import (
    DEFAULT_LOG_LEVEL,
    DEFAULT_MQTT_BROKER_ADDRESS,
    DEFAULT_MQTT_BROKER_PORT,
    DEFAULT_PID_FILE,
    DEFAULT_PRODUCTS_DIRECTORY,
    Config,
)
from notus.scanner.errors import ConfigFileError


class ConfigTestCase(unittest.TestCase):
    def test_config_defaults(self):
        config = Config()

        config_data = config.values()

        self.assertEqual(
            config_data.get("products-directory"),
            DEFAULT_PRODUCTS_DIRECTORY,
        )
        self.assertIsNone(config_data.get("log-file"))
        self.assertEqual(config_data.get("log-level"), DEFAULT_LOG_LEVEL)
        self.assertEqual(
            config_data.get("mqtt-broker-address"), DEFAULT_MQTT_BROKER_ADDRESS
        )
        self.assertEqual(
            config_data.get("mqtt-broker-port"), DEFAULT_MQTT_BROKER_PORT
        )
        self.assertEqual(config_data.get("pid-file"), DEFAULT_PID_FILE)

    @patch("pathlib.Path")
    def test_parsing_config_file(self, path_mock):
        path_mock.read_text.return_value = """[notus-scanner]
        products-directory = "/a/b"
        log-file = "/bar/foo"
        log-level = "DEBUG"
        mqtt-broker-address = "1.2.3.4"
        mqtt-broker-port = 1234
        pid-file = "/foo/bar"
        """

        config = Config()
        config.load(path_mock)

        config_data = config.values()

        self.assertEqual(config_data.get("products-directory"), "/a/b")
        self.assertEqual(config_data.get("log-file"), "/bar/foo")
        self.assertEqual(config_data.get("log-level"), "DEBUG")
        self.assertEqual(config_data.get("mqtt-broker-address"), "1.2.3.4")
        self.assertEqual(config_data.get("mqtt-broker-port"), 1234)
        self.assertEqual(config_data.get("pid-file"), "/foo/bar")

    @patch("pathlib.Path")
    def test_parsing_invalid_toml_file(self, path_mock):
        path_mock.read_text.return_value = """[notus-scanner]
        pid-file = /foo/bar
        """

        config = Config()

        with self.assertRaises(ConfigFileError):
            config.load(path_mock)

    @patch("pathlib.Path")
    def test_parsing_unknown_values(self, path_mock):
        path_mock.read_text.return_value = """[notus-scanner]
        products-directory = "/a/b"
        foo = "bar"
        """

        config = Config()
        config.load(path_mock)

        config_data = config.values()
        self.assertEqual(config_data.get("products-directory"), "/a/b")
        self.assertIsNone(config_data.get("foo"))

    @patch.dict(
        "os.environ",
        {
            "NOTUS_SCANNER_PRODUCTS_DIRECTORY": "/path/env/a",
            "NOTUS_SCANNER_LOG_FILE": "/path/env/b",
            "NOTUS_SCANNER_LOG_LEVEL": "WARN",
            "NOTUS_SCANNER_MQTT_BROKER_ADDRESS": "4.3.2.1",
            "NOTUS_SCANNER_MQTT_BROKER_PORT": "9876",
            "NOTUS_SCANNER_PID_FILE": "/path/env/c",
        },
        clear=True,
    )
    @patch("pathlib.Path")
    def test_parsing_environment_preference(self, path_mock):
        path_mock.read_text.return_value = """[notus-scanner]
        products-directory = "/path/config/a"
        log-file = "/path/config/b"
        log-level = "DEBUG"
        mqtt-broker-address = "1.2.3.4"
        mqtt-broker-port = 1234
        pid-file = "/path/config/c"
        """

        config = Config()
        config.load(path_mock)

        config_data = config.values()

        self.assertEqual(config_data.get("products-directory"), "/path/env/a")
        self.assertEqual(config_data.get("log-file"), "/path/env/b")
        self.assertEqual(config_data.get("log-level"), "WARN")
        self.assertEqual(config_data.get("mqtt-broker-address"), "4.3.2.1")
        self.assertEqual(config_data.get("mqtt-broker-port"), "9876")
        self.assertEqual(config_data.get("pid-file"), "/path/env/c")
