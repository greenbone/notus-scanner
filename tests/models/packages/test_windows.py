# SPDX-FileCopyrightText: 2021-2025 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest import TestCase

from notus.scanner.models.packages.windows import WindowsPackage


class WindowsPackageTestCase(TestCase):
    def test_compare_gt(self):
        package1 = WindowsPackage(
            name="Windows Server 2025 x64",
            full_version="10.0.26100.1",
            full_name="Windows Server 2025 x64;10.0.26100.1",
            prefix="10.0.26100",
            build="1",
        )
        package2 = WindowsPackage(
            name="Windows Server 2025 x64",
            full_version="10.0.26100.2",
            full_name="Windows Server 2025 x64;10.0.26100.2",
            prefix="10.0.26100",
            build="2",
        )

        self.assertGreater(package2, package1)

    def test_compare_gt_different_name(self):
        package1 = WindowsPackage(
            name="Windows Server 2025 x64",
            full_version="10.0.26100.1",
            full_name="Windows Server 2025 x64;10.0.26100.1",
            prefix="10.0.26100",
            build="1",
        )
        package2 = WindowsPackage(
            name="Windows Server 2024 x64",
            full_version="10.0.26100.1",
            full_name="Windows Server 2025 x64;10.0.26100.1",
            prefix="10.0.26100",
            build="1",
        )

        self.assertFalse(package1 > package2)
        self.assertFalse(package2 > package1)

    def test_compare_equal(self):
        package1 = WindowsPackage(
            name="Windows Server 2025 x64",
            full_version="10.0.26100.1",
            full_name="Windows Server 2025 x64;10.0.26100.1",
            prefix="10.0.26100",
            build="1",
        )
        package2 = WindowsPackage(
            name="Windows Server 2025 x64",
            full_version="10.0.26100.1",
            full_name="Windows Server 2025 x64;10.0.26100.1",
            prefix="10.0.26100",
            build="1",
        )

        self.assertEqual(package2, package1)

    def test_from_full_name(self):
        package = WindowsPackage.from_full_name("")
        self.assertIsNone(package)
        package = WindowsPackage.from_full_name("3447")
        self.assertIsNone(package)
        package = WindowsPackage.from_full_name(
            "Windows Server 2025 x64;10.0.26100.1000"
        )
        self.assertEqual(package.name, "Windows Server 2025 x64")
        self.assertEqual(package.full_version, "10.0.26100.1000")
        self.assertEqual(
            package.full_name, "Windows Server 2025 x64;10.0.26100.1000"
        )
        self.assertEqual(package.prefix, "10.0.26100")
        self.assertEqual(package.build, "1000")

    def test_from_name_and_full_version(self):
        package = WindowsPackage.from_name_and_full_version("", "")
        self.assertIsNone(package)
        package = WindowsPackage.from_name_and_full_version("10.0.22631", "")
        self.assertIsNone(package)
        package = WindowsPackage.from_name_and_full_version("", "3447")
        self.assertIsNone(package)
        package = WindowsPackage.from_name_and_full_version(
            "Windows Server 2025 x64", "10.0.26100.1000"
        )
        self.assertEqual(package.name, "Windows Server 2025 x64")
        self.assertEqual(package.full_version, "10.0.26100.1000")
        self.assertEqual(
            package.full_name, "Windows Server 2025 x64;10.0.26100.1000"
        )
        self.assertEqual(package.prefix, "10.0.26100")
        self.assertEqual(package.build, "1000")
