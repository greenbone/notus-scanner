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

from pathlib import Path
from unittest import TestCase

from notus.scanner.errors import AdvisoriesLoadingError
from notus.scanner.loader.gpg_sha_verifier import VerificationResult
from notus.scanner.loader.json import JSONAdvisoriesLoader
from notus.scanner.models.packages.rpm import RPMPackage

_here = Path(__file__).parent


class JSONAdvisoriesLoaderTestCase(TestCase):
    def test_unknown_file(self):
        loader = JSONAdvisoriesLoader(
            advisories_directory_path=_here,
            verify=lambda _: VerificationResult.SUCCESS,
        )

        self.assertIsNone(loader.load_package_advisories("foo"))

    def test_verification_failure(self):
        loader = JSONAdvisoriesLoader(
            advisories_directory_path=_here,
            verify=lambda _: VerificationResult.INVALID_HASH,
        )
        with self.assertRaises(AdvisoriesLoadingError):
            loader.load_package_advisories("EmptyOS")

    def test_empty_file(self):
        loader = JSONAdvisoriesLoader(
            advisories_directory_path=_here,
            verify=lambda _: VerificationResult.SUCCESS,
        )

        advisories = loader.load_package_advisories("EmptyOS")
        self.assertIsNone(advisories)

    def test_example(self):
        loader = JSONAdvisoriesLoader(
            advisories_directory_path=_here,
            verify=lambda _: VerificationResult.SUCCESS,
        )

        advisories = loader.load_package_advisories("EulerOS V2.0SP1")
        if not advisories:
            self.fail("Advisories are none")
        self.assertIsNotNone(advisories)
        self.assertEqual(len(advisories), 55)

        package1 = RPMPackage.from_full_name("openssh-6.6.1p1-25.4.h3.x86_64")
        if not package1:
            self.fail("package1 is None")
        package2 = RPMPackage.from_full_name(
            "openssh-clients-6.6.1p1-25.4.h3.x86_64"
        )

        if not package2:
            self.fail("package2 is None")
        package_advisories1 = advisories.get_package_advisories_for_package(
            package1
        )
        package_advisories2 = advisories.get_package_advisories_for_package(
            package2
        )

        oid = "1.3.6.1.4.1.25623.1.1.2.2016.1008"

        self.assertEqual(len(package_advisories1), 1)
        self.assertEqual(len(package_advisories2), 1)

        self.assertIn(oid, package_advisories1.keys())
        self.assertIn(oid, package_advisories2.keys())

        package_advisories1 = package_advisories1[oid]
        package_advisories2 = package_advisories2[oid]

        # get first PackageAdvisory from the sets
        package_advisory1 = next(iter(package_advisories1))
        package_advisory2 = next(iter(package_advisories2))

        self.assertEqual(package_advisory1.oid, package_advisory2.oid)

        advisory = package_advisory1.oid

        self.assertEqual(advisory, "1.3.6.1.4.1.25623.1.1.2.2016.1008")

    def test_invalid_package_type(self):
        loader = JSONAdvisoriesLoader(
            advisories_directory_path=_here,
            verify=lambda _: VerificationResult.SUCCESS,
        )

        advisory = loader.load_package_advisories("invalid_package")

        self.assertIsNone(advisory)
