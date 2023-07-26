# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from unittest import TestCase

from notus.scanner.errors import AdvisoriesLoadingError
from notus.scanner.loader.gpg_sha_verifier import VerificationResult
from notus.scanner.loader.json import JSONAdvisoriesLoader
from notus.scanner.models.packages.deb import DEBPackage
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
            package1.name
        )
        package_advisories2 = advisories.get_package_advisories_for_package(
            package2.name
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

    def test_example_range(self):
        loader = JSONAdvisoriesLoader(
            advisories_directory_path=_here,
            verify=lambda _: VerificationResult.SUCCESS,
        )

        advisories = loader.load_package_advisories("range")
        if not advisories:
            self.fail("Advisories are none")
        self.assertIsNotNone(advisories)
        self.assertEqual(len(advisories), 4)

        package1 = DEBPackage.from_name_and_full_version("gitlab-ce", "15.11.1")
        if not package1:
            self.fail("package1 is None")

        package2 = DEBPackage.from_name_and_full_version("gitlab-ce", "15.10.1")
        if not package2:
            self.fail("package2 is None")
        package_advisories = advisories.get_package_advisories_for_package(
            package1.name
        )

        oid = "1.3.6.1.4.1.25623.1.1.7.2.2023.10089729899100"

        self.assertEqual(len(package_advisories), 1)

        self.assertIn(oid, package_advisories.keys())

        package_advisories = package_advisories[oid]

        # get first PackageAdvisory from the sets
        package_advisory = next(iter(package_advisories))

        advisory = package_advisory.oid

        self.assertEqual(
            advisory, "1.3.6.1.4.1.25623.1.1.7.2.2023.10089729899100"
        )

        vul_detect1 = 0
        vul_detect2 = 0
        for package_advisory in package_advisories:
            if package_advisory.is_vulnerable(package1):
                vul_detect1 += 1
            if package_advisory.is_vulnerable(package2):
                vul_detect2 += 1
        self.assertEqual(2, vul_detect1)
        self.assertEqual(0, vul_detect2)

    def test_invalid_package_type(self):
        loader = JSONAdvisoriesLoader(
            advisories_directory_path=_here,
            verify=lambda _: VerificationResult.SUCCESS,
        )

        advisory = loader.load_package_advisories("invalid_package")

        self.assertIsNone(advisory)
