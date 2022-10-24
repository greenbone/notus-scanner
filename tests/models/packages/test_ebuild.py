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
            fullname = file.readline()
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
