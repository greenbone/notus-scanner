# Copyright (C) 2021 Greenbone Networks GmbH
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

import json
import unittest
from pathlib import Path
from typing import List, Optional, Tuple

from notus.scanner.loader.gpg_sha_verifier import VerificationResult
from notus.scanner.loader.json import JSONAdvisoriesLoader
from notus.scanner.messages.message import Message
from notus.scanner.messages.start import ScanStartMessage
from notus.scanner.messaging.publisher import Publisher
from notus.scanner.scanner import NotusScanner

_here = Path(__file__).parent


class FakePublisher(Publisher):
    def __init__(self):
        self.results = []

    def publish(self, message: Message) -> None:
        serialized = message.serialize()
        values = str(serialized.get("value", "")).split("\n")
        for value in values:
            if value.find("Installed version:") >= 0:
                installed = value.split(":")[1].strip()
                self.results.append(installed)


class VerifierTestCase(unittest.TestCase):
    """
    VerifierTestCase loads a notus advisory for FakeSpecifierOS
    and iterates through defined fixed packages and their specifier
    to generate and test them.
    """

    def per_symbol(
        self, name: str, verifier: Optional[str]
    ) -> Tuple[List[str], List[str]]:
        """
        returns not_in_result and in result
        """
        greater = lambda: name.replace("15", "16")
        smaller = lambda: name.replace("15", "14")
        if not verifier:
            return [greater(), name], [smaller()]
        if verifier == ">":
            return [greater()], [name, smaller()]
        if verifier == ">=":
            return [greater(), name], [smaller()]
        if verifier == "<":
            return [smaller()], [name, greater()]
        if verifier == "<=":
            return [smaller(), name], [greater()]
        return [name], [smaller(), greater()]

    def generate_test_cases(self):
        jdict = json.loads((_here / "fakespecifier_os.notus").read_bytes())
        fixed_packages = (
            f.get("fixed_packages", []) for f in jdict.get("advisories", {})
        )
        cases = (
            (fp.get("full_name"), fp.get("specifier"))
            for fps in fixed_packages
            for fp in fps
        )
        # cases that should not appear in result
        not_in = []
        # cases that should appear in result
        is_in = []
        for case in cases:
            c_not_in, c_is_in = self.per_symbol(*case)
            not_in = not_in + c_not_in
            is_in = is_in + c_is_in
        # packagelist is both combined
        return not_in + is_in, not_in, is_in

    def test_verifier(self):
        loader = JSONAdvisoriesLoader(
            advisories_directory_path=_here,
            verify=lambda _: VerificationResult.SUCCESS,
        )
        publisher = FakePublisher()
        scanner = NotusScanner(loader, publisher)
        pkg_list, not_in_results, in_results = self.generate_test_cases()
        msg = ScanStartMessage(
            scan_id="scanus praktikus",
            os_release="FakeSpecifier OS",
            host_ip="127.0.0.2",
            host_name="localhorst",
            package_list=pkg_list,
        )
        scanner.run_scan(msg)
        results = set(publisher.results)

        self.assertEqual(len(results), len(publisher.results))

        self.assertEqual(
            set(),
            results.intersection(not_in_results),
        )

        self.assertEqual(set(in_results), results.intersection(in_results))
