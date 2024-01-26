# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from unittest import TestCase

from notus.scanner.models.packages.ebuild import EBuildPackage


class EBuildPackageTestCase(TestCase):
    def test_parse_fullname(self):
        """
        verifies if ebuild id able to parse the fullname examples provided by
        gentoo_examples.txt
        """
        currentp = Path(__file__).parent
        with (currentp / "gentoo_examples.txt").open(
            "r", encoding="utf-8"
        ) as file:
            for fullname in file.readlines():
                if not EBuildPackage.from_full_name(fullname):
                    self.fail(f"{fullname} is not parsable for EBuildPackage.")

    def test_guard(self):
        self.assertIsNone(EBuildPackage.from_full_name(""))
        self.assertIsNone(EBuildPackage.from_full_name("www-servers/"))
        self.assertIsNone(EBuildPackage.from_full_name("www-servers/name"))
        self.assertIsNone(EBuildPackage.from_name_and_full_version("", "1.2.3"))
        self.assertIsNone(EBuildPackage.from_name_and_full_version("name", ""))

    def test_comparability(self):
        apache1 = EBuildPackage.from_full_name("www-servers/apache-2.4.51-r2")
        apache2 = EBuildPackage.from_name_and_full_version(
            "www-servers/apache", "2.4.51-r3"
        )
        if not apache1 or not apache2:
            self.fail("Unable to parse packages")
        self.assertGreater(apache2, apache1)
        self.assertLess(apache1, apache2)
        apache3 = EBuildPackage.from_name_and_full_version(
            "www-servers/apache", "2.4.51-r3"
        )
        if not apache3:
            self.fail("Unable to parse package")
        self.assertGreaterEqual(apache2, apache3)
        self.assertLessEqual(apache2, apache3)
        apache4 = EBuildPackage.from_name_and_full_version(
            "apache", "2.4.51-r3"
        )
        if not apache4:
            self.fail("Unable to parse package")
        # www-servers is a part of the name hence not comparable
        self.assertNotEqual(apache4, apache3)
