# SPDX-FileCopyrightText: 2021-2025 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest import TestCase

from notus.scanner.models.packages.windows import WindowsPackage


class WindowsPackageTestCase(TestCase):
    def test_compare_gt(self):
        package1 = WindowsPackage(
            name="10.0.22631",
            full_version="3447",
            full_name="10.0.22631.3447",
        )
        package2 = WindowsPackage(
            name="10.0.22631",
            full_version="3448",
            full_name="10.0.22631.3449",
        )

        self.assertGreater(package2, package1)

    def test_compare_gt_different_name(self):
        package1 = WindowsPackage(
            name="10.0.22631",
            full_version="3447",
            full_name="10.0.22631.3447",
        )
        package2 = WindowsPackage(
            name="10.0.22632",
            full_version="3447",
            full_name="10.0.22632.3447",
        )

        self.assertFalse(package1 > package2)
        self.assertFalse(package2 > package1)

    def test_compare_less(self):
        package1 = WindowsPackage(
            name="10.0.22631",
            full_version="3447",
            full_name="10.0.22631.3447",
        )
        package2 = WindowsPackage(
            name="10.0.22631",
            full_version="3446",
            full_name="10.0.22631.3446",
        )

        self.assertLess(package2, package1)

    def test_compare_equal(self):
        package1 = WindowsPackage(
            name="10.0.22631",
            full_version="3447",
            full_name="10.0.22631.3447",
        )
        package2 = WindowsPackage(
            name="10.0.22631",
            full_version="3447",
            full_name="10.0.22631.3447",
        )

        self.assertEqual(package2, package1)

    def test_from_full_name(self):
        package = WindowsPackage.from_full_name("")
        self.assertIsNone(package)
        package = WindowsPackage.from_full_name("3447")
        self.assertIsNone(package)
        package = WindowsPackage.from_full_name("10.0.22631.3447")
        self.assertEqual(package.name, "10.0.22631")
        self.assertEqual(package.full_version, "3447")
        self.assertEqual(package.full_name, "10.0.22631.3447")

    def test_from_name_and_full_version(self):
        package = WindowsPackage.from_name_and_full_version("", "")
        self.assertIsNone(package)
        package = WindowsPackage.from_name_and_full_version("10.0.22631", "")
        self.assertIsNone(package)
        package = WindowsPackage.from_name_and_full_version("", "3447")
        self.assertIsNone(package)
        package = WindowsPackage.from_name_and_full_version(
            "10.0.22631", "3447"
        )
        self.assertEqual(package.name, "10.0.22631")
        self.assertEqual(package.full_version, "3447")
        self.assertEqual(package.full_name, "10.0.22631.3447")
