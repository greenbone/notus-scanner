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
    create_parser,
    Arguments,
    DEFAULT_CONFIG_PATH,
)


class CliParserTestCase(unittest.TestCase):
    def setUp(self):
        self.parser = create_parser('Wrapper name')

    def parse_args(self, args: List[str]) -> Arguments:
        return self.parser.parse_arguments(args)

    @patch('sys.stderr', new_callable=StringIO)
    def test_parse_args_no_module(self, _mock_stderr):
        args = self.parse_args([])
        self.assertEqual(None, args.module)

    @patch('sys.stderr', new_callable=StringIO)
    def test_parse_args_unsupported_module(self, _mock_stderr):
        args = self.parse_args(['AnyModule'])
        self.assertEqual(None, args.module)

    def test_mqtt_broker(self):
        args = self.parse_args(['EulerOS', '--mqtt=localhost'])
        self.assertEqual('localhost', args.mqtt)

    def test_correct_upper_case_log_level(self):
        args = self.parse_args(['EulerOS', '--log-level=ERROR'])
        self.assertEqual('ERROR', args.log_level)

    def test_correct_lower_case_log_level(self):
        args = self.parse_args(['EulerOS', '-L info'.split()])
        self.assertEqual('INFO', args.log_level)

    def test_metadata_directory(self):
        args = self.parse_args(['EulerOS', '--metadata-directory=/tmp'])
        self.assertEqual(Path('/tmp'), args.metadata_directory)

    def test_arg_host(self):
        args = self.parse_args(['EulerOS', '--host=192.168.1.1'])
        self.assertEqual('192.168.1.1', args.host)

    def test_arg_hostname(self):
        args = self.parse_args(['EulerOS', '--hostname=localhost'])
        self.assertEqual('localhost', args.hostname)

    @patch('sys.stderr', new_callable=StringIO)
    def test_no_dir(self, _mock_stderr):
        with self.assertRaises(SystemExit):
            self.parse_args(['EulerOS', '--metadata-directory=/foobarbaz'])

    def test_defaults(self):
        args = self.parse_args(['EulerOS'])

        self.assertEqual(args.config, DEFAULT_CONFIG_PATH)
