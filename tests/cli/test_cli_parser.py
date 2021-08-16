# Copyright (C) 2020-2021 Greenbone Networks GmbH
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

""" Test module for command line arguments.
"""

import unittest

from unittest.mock import patch


from io import StringIO
from pathlib import Path
from typing import List

from notus.scanner.cli.parser import (
    DEFAULT_MQTT_BROKER_PORT,
    DEFAULT_PID_PATH,
    create_parser,
    Arguments,
    DEFAULT_CONFIG_PATH,
)


class CliParserTestCase(unittest.TestCase):
    def setUp(self):
        self.parser = create_parser('Wrapper name')

    def parse_args(self, args: List[str]) -> Arguments:
        return self.parser.parse_arguments(args)

    def parse_args_with_required_args(self, args: List[str]) -> Arguments:
        required_args = ['--mqtt-broker-address=localhost']
        required_args.extend(args)
        return self.parse_args(required_args)

    def test_mqtt_broker(self):
        args = self.parse_args(['--mqtt-broker-address=localhost'])
        self.assertEqual('localhost', args.mqtt_broker_address)

        args = self.parse_args(['-b', 'localhost'])
        self.assertEqual('localhost', args.mqtt_broker_address)

    def test_mqtt_broker_port(self):
        args = self.parse_args_with_required_args(['--mqtt-broker-port=12345'])
        self.assertEqual(args.mqtt_broker_port, 12345)

        args = self.parse_args_with_required_args(['-p', '12345'])
        self.assertEqual(args.mqtt_broker_port, 12345)

    def test_correct_upper_case_log_level(self):
        args = self.parse_args_with_required_args(['--log-level=ERROR'])
        self.assertEqual('ERROR', args.log_level)

    def test_correct_lower_case_log_level(self):
        args = self.parse_args_with_required_args(['-L', 'info'])
        self.assertEqual('INFO', args.log_level)

    def test_advisories_directory(self):
        args = self.parse_args_with_required_args(
            ['--advisories-directory=/tmp']
        )
        self.assertEqual(Path('/tmp'), args.advisories_directory)

        args = self.parse_args_with_required_args(['-a', '/tmp'])
        self.assertEqual(Path('/tmp'), args.advisories_directory)

    @patch('sys.stderr', new_callable=StringIO)
    def test_advisories_directory_not_exists(self, _mock_stderr):
        with self.assertRaises(SystemExit):
            self.parse_args_with_required_args(
                ['--advisories-directory=/foobarbaz']
            )

    def test_pid_file(self):
        args = self.parse_args_with_required_args(['--pid-file=/foo/bar'])
        self.assertEqual(args.pid_file, '/foo/bar')

    def test_log_file(self):
        args = self.parse_args_with_required_args(['--log-file=/foo/bar'])
        self.assertEqual(args.log_file, '/foo/bar')

        args = self.parse_args_with_required_args(['-l', '/foo/bar'])
        self.assertEqual(args.log_file, '/foo/bar')

    def test_foreground(self):
        args = self.parse_args_with_required_args(['--foreground'])
        self.assertTrue(args.foreground)

        args = self.parse_args_with_required_args(['-f'])
        self.assertTrue(args.foreground)

    def test_defaults(self):
        args = self.parse_args_with_required_args([])

        self.assertEqual(args.config, DEFAULT_CONFIG_PATH)
        self.assertEqual(args.mqtt_broker_port, DEFAULT_MQTT_BROKER_PORT)
        self.assertEqual(args.pid_file, DEFAULT_PID_PATH)
        self.assertEqual(args.log_level, 'INFO')
        self.assertFalse(args.foreground)
