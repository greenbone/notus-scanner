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

from unittest import TestCase

from notus.scanner.models.packages.slackware import SlackPackage


class SlackPackageTestCase(TestCase):
    def test_compare_gt(self):
        """packages should be comparable"""
        package1 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="4",
            arch="x86_64",
            target="15.0",
            full_name="foo-bar-1.2.3-x86_64-4_slack15.0",
            full_version="1.2.3-x86_64-4_slack15.0",
        )
        package2 = SlackPackage(
            name="foo-bar",
            version="1.2.4",
            build="4",
            arch="x86_64",
            target="15.0",
            full_name="foo-bar-1.2.4-x86_64-4_slack15.0",
            full_version="1.2.4-x86_64-4_slack15.0",
        )
        self.assertGreater(package2, package1)

        package2 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="5",
            arch="x86_64",
            target="15.0",
            full_name="foo-bar-1.2.3-x86_64-5_slack15.0",
            full_version="1.2.3-x86_64-5_slack15.0",
        )
        self.assertGreater(package2, package1)

        package2 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="4",
            arch="x86_64",
            target="15.1",
            full_name="foo-bar-1.2.3-x86_64-4_slack15.1",
            full_version="1.2.3-x86_64-4_slack15.1",
        )
        self.assertGreater(package2, package1)

    def test_compare_gt_different_architecture(self):
        """packages of different architecture should not be comparable"""
        package1 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="4",
            arch="x86_64",
            target="15.0",
            full_name="foo-bar-1.2.3-x86_64-4_slack15.0",
            full_version="1.2.3-x86_64-4_slack15.0",
        )
        package2 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="4",
            arch="aarch64",
            target="15.0",
            full_name="foo-bar-1.2.3-aarch64-4_slack15.0",
            full_version="1.2.3-aarch64-4_slack15.0",
        )
        package3 = SlackPackage(
            name="foo-bar",
            version="1.2.4",
            build="4",
            arch="aarch64",
            target="15.0",
            full_name="foo-bar-1.2.4-aarch64-4_slack15.0",
            full_version="1.2.4-aarch64-4_slack15.0",
        )
        package4 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="5",
            arch="aarch64",
            target="15.0",
            full_name="foo-bar-1.2.3-aarch64-5_slack15.0",
            full_version="1.2.3-aarch64-5_slack15.0",
        )
        package5 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="4",
            arch="aarch64",
            target="15.1",
            full_name="foo-bar-1.2.3-aarch64-4_slack15.1",
            full_version="1.2.3-aarch64-4_slack15.1",
        )
        self.assertFalse(package2 > package1)
        self.assertFalse(package1 > package2)
        self.assertFalse(package3 > package1)
        self.assertFalse(package1 > package3)
        self.assertFalse(package4 > package1)
        self.assertFalse(package1 > package4)
        self.assertFalse(package5 > package1)
        self.assertFalse(package1 > package5)

    def test_compare_gt_different_name(self):
        """different packagtes should not be comparable"""
        package1 = SlackPackage(
            name="foo",
            version="1.2.3",
            build="4",
            arch="x86_64",
            target="15.0",
            full_name="foo-1.2.3-x86_64-4_slack15.0",
            full_version="1.2.3-x86_64-4_slack15.0",
        )
        package2 = SlackPackage(
            name="bar",
            version="1.2.3",
            build="4",
            arch="x86_64",
            target="15.0",
            full_name="bar-1.2.3-x86_64-4_slack15.0",
            full_version="1.2.3-x86_64-4_slack15.0",
        )
        self.assertFalse(package2 > package1)
        self.assertFalse(package1 > package2)

    def test_compare_less(self):
        """packages should be comparable"""
        package1 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="4",
            arch="x86_64",
            target="15.0",
            full_name="foo-bar-1.2.3-x86_64-4_slack15.0",
            full_version="1.2.3-x86_64-4_slack15.0",
        )
        package2 = SlackPackage(
            name="foo-bar",
            version="1.2.4",
            build="4",
            arch="x86_64",
            target="15.0",
            full_name="foo-bar-1.2.4-x86_64-4_slack15.0",
            full_version="1.2.4-x86_64-4_slack15.0",
        )
        self.assertLess(package1, package2)

        package2 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="5",
            arch="x86_64",
            target="15.0",
            full_name="foo-bar-1.2.3-x86_64-5_slack15.0",
            full_version="1.2.3-x86_64-5_slack15.0",
        )
        self.assertLess(package1, package2)

        package2 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="4",
            arch="x86_64",
            target="15.1",
            full_name="foo-bar-1.2.3-x86_64-4_slack15.1",
            full_version="1.2.3-x86_64-4_slack15.1",
        )
        self.assertLess(package1, package2)

    def test_compare_equal(self):
        """packages with the same data should be equal"""
        package1 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="4",
            arch="x86_64",
            target="15.0",
            full_name="foo-bar-1.2.3-x86_64-4_slack15.0",
            full_version="1.2.3-x86_64-4_slack15.0",
        )
        package2 = SlackPackage(
            name="foo-bar",
            version="1.2.3",
            build="4",
            arch="x86_64",
            target="15.0",
            full_name="foo-bar-1.2.3-x86_64-4_slack15.0",
            full_version="1.2.3-x86_64-4_slack15.0",
        )

        self.assertEqual(package1, package2)

    def test_from_full_name(self):
        """it should be possible to create packages via the full name"""
        self.assertIsNone(SlackPackage.from_full_name(None))

        package = SlackPackage.from_full_name("flac-1.3.4-foo-1_slack15.0")
        self.assertEqual(package.arch, "foo")

        package = SlackPackage.from_full_name("flac-1.3.4-x86_64-1_slack15.0")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "flac")
        self.assertEqual(package.version, "1.3.4")
        self.assertEqual(package.build, "1")
        self.assertEqual(package.target, "15.0")
        self.assertEqual(package.full_version, "1.3.4-x86_64-1_slack15.0")
        self.assertEqual(package.full_name, "flac-1.3.4-x86_64-1_slack15.0")

        package = SlackPackage.from_full_name("kernel-source-5.15.27-noarch-1")
        self.assertEqual(package.arch, "noarch")
        self.assertEqual(package.name, "kernel-source")
        self.assertEqual(package.version, "5.15.27")
        self.assertEqual(package.build, "1")
        self.assertEqual(package.target, "")
        self.assertEqual(package.full_version, "5.15.27-noarch-1")
        self.assertEqual(package.full_name, "kernel-source-5.15.27-noarch-1")

        package = SlackPackage.from_full_name("libjpeg-v8a-x86_64-2")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "libjpeg")
        self.assertEqual(package.version, "v8a")
        self.assertEqual(package.build, "2")
        self.assertEqual(package.target, "")
        self.assertEqual(package.full_version, "v8a-x86_64-2")
        self.assertEqual(package.full_name, "libjpeg-v8a-x86_64-2")

        package = SlackPackage.from_full_name(" libjpeg-v8a-x86_64-2\r\n")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "libjpeg")
        self.assertEqual(package.version, "v8a")
        self.assertEqual(package.build, "2")
        self.assertEqual(package.target, "")
        self.assertEqual(package.full_version, "v8a-x86_64-2")
        self.assertEqual(package.full_name, "libjpeg-v8a-x86_64-2")

        package = SlackPackage.from_full_name("libjpeg-v8a-x86_64")
        self.assertIsNone(package)

        package = SlackPackage.from_full_name("libjpeg-v8a-foo-2")
        self.assertEqual(package.arch, "foo")

    def test_from_name_and_full_version(self):
        """it should be possible to create packages from name and full
        version"""
        self.assertIsNone(SlackPackage.from_name_and_full_version(None, None))

        package = SlackPackage.from_name_and_full_version(
            "flac", "1.3.4-x86_64-1_slack15.0"
        )
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "flac")
        self.assertEqual(package.version, "1.3.4")
        self.assertEqual(package.build, "1")
        self.assertEqual(package.target, "15.0")
        self.assertEqual(package.full_version, "1.3.4-x86_64-1_slack15.0")
        self.assertEqual(package.full_name, "flac-1.3.4-x86_64-1_slack15.0")

        package = SlackPackage.from_name_and_full_version(
            "flac", "1.3.4-x86_64"
        )
        self.assertIsNone(package)

        package = SlackPackage.from_name_and_full_version("flac", "1.3.4-foo-1")
        self.assertEqual(package.arch, "foo")
