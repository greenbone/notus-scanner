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

from dataclasses import FrozenInstanceError
from unittest import TestCase

from notus.scanner.errors import PackageError
from notus.scanner.models.packages.deb import DEBPackage
from notus.scanner.models.packages.package import (
    Package,
    PackageAdvisories,
    PackageAdvisory,
    PackageComparison,
    PackageType,
)
from notus.scanner.models.packages.rpm import RPMPackage


class PackageTestCase(TestCase):
    def test_matching_hashes(self):
        """hashes for the same package should match"""
        package1 = Package(
            name="foo-bar",
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = Package(
            name="foo-bar",
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )

        self.assertEqual(hash(package1), hash(package2))

    def test_not_matching_hashes(self):
        """hashes for different packages should not match"""
        package1 = Package(
            name="foo-bar",
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = Package(
            name="foo-bar",
            full_name="foo-bar-1.2.4-4.x86_64",
            full_version="1.2.4-4.x86_64",
        )

        self.assertNotEqual(hash(package1), hash(package2))

    def test_gt_package_error(self):
        package1 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="4",
            arch="x86_64",
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = DEBPackage(
            name="foo-bar",
            epoch="1",
            upstream_version="1.2.4",
            debian_revision="4",
            full_name="foo-bar-1.2.4-4.x86_64",
            full_version="1.2.4-4.x86_64",
        )
        with self.assertRaises(PackageError):
            if package1 > package2:
                self.fail("PackageError should occur")

    def test_version_compare(self):
        version_a = "1.2.3"
        version_b = "1.2.3"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.EQUAL)

        version_a = "1.2.3"
        version_b = "1.2.12"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.B_NEWER)

        version_a = "1.2.3"
        version_b = "1.2.3a"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.B_NEWER)

        version_a = "1.2.3~rc0"
        version_b = "1.2.3"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.B_NEWER)

        version_a = "1.2.3a"
        version_b = "1.2.3b"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.B_NEWER)

        version_a = "1.2.3a"
        version_b = "1.2.3-2"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.B_NEWER)

        version_a = "1.2"
        version_b = "1.2.3"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.B_NEWER)

        version_a = "1.1.1c"
        version_b = "1.1.1k"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.B_NEWER)

        version_a = "1.2.3.1"
        version_b = "1.2.3_a"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.B_NEWER)

        version_a = "1.2.3_a"
        version_b = "1.2.3_1"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.B_NEWER)

        version_a = "20211016ubuntu0.20.04.1"
        version_b = "20211016~20.04.1"
        ret = Package.version_compare(version_a, version_b)
        self.assertEqual(ret, PackageComparison.A_NEWER)
        ret = Package.version_compare(version_a=version_b, version_b=version_a)
        self.assertEqual(ret, PackageComparison.B_NEWER)


class PackageAdvisoryTestCase(TestCase):
    def test_constructor(self):
        package = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        advisory = "1.2.3.4.5"

        package_advisory = PackageAdvisory(
            package=package,
            oid=advisory,
            symbol=">=",
            is_vulnerable=lambda _: False,
        )

        self.assertEqual(package_advisory.package, package)
        self.assertEqual(package_advisory.oid, advisory)

    def test_immutability(self):
        package1 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        package2 = RPMPackage.from_full_name(
            "bar-1.2.3-3.aarch64",
        )
        advisory1 = "1.2.3.4.5"
        advisory2 = "1.2.3.4.6"

        package_advisory = PackageAdvisory(
            package=package1,
            oid=advisory1,
            symbol=">=",
            is_vulnerable=lambda _: False,
        )

        with self.assertRaises(FrozenInstanceError):
            package_advisory.package = package2

        with self.assertRaises(FrozenInstanceError):
            package_advisory.oid = advisory2

        self.assertEqual(package_advisory.package, package1)
        self.assertEqual(package_advisory.oid, advisory1)

    def test_equal(self):
        package1 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        package2 = RPMPackage.from_full_name(
            "bar-1.2.3-3.aarch64",
        )
        advisory1 = "1.2.3.4.5"
        advisory2 = "1.2.3.4.6"

        package_advisory1 = PackageAdvisory(
            package=package1,
            oid=advisory1,
            symbol=">=",
            is_vulnerable=lambda _: False,
        )
        package_advisory2 = PackageAdvisory(
            package=package2,
            oid=advisory2,
            symbol=">=",
            is_vulnerable=lambda _: False,
        )
        package_advisory3 = PackageAdvisory(
            package=package1,
            oid=advisory1,
            symbol=">=",
            is_vulnerable=lambda _: False,
        )
        package_advisory4 = PackageAdvisory(
            package=package1,
            oid=advisory2,
            symbol=">=",
            is_vulnerable=lambda _: False,
        )

        self.assertEqual(package_advisory1, package_advisory1)
        self.assertEqual(package_advisory1, package_advisory3)
        self.assertNotEqual(package_advisory2, package_advisory3)
        self.assertNotEqual(package_advisory1, package_advisory2)
        self.assertNotEqual(package_advisory1, package_advisory4)
        self.assertNotEqual(package_advisory2, package_advisory4)

    def test_hash(self):
        package1 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        package2 = RPMPackage.from_full_name(
            "bar-1.2.3-3.aarch64",
        )
        advisory1 = "1.2.3.4.5"

        advisory2 = "1.2.3.4.6"

        package_advisory1 = PackageAdvisory(
            package=package1,
            oid=advisory1,
            symbol=">=",
            is_vulnerable=lambda _: False,
        )
        package_advisory2 = PackageAdvisory(
            package=package2,
            oid=advisory2,
            symbol=">=",
            is_vulnerable=lambda _: False,
        )
        package_advisory3 = PackageAdvisory(
            package=package1,
            oid=advisory1,
            symbol=">=",
            is_vulnerable=lambda _: False,
        )
        package_advisory4 = PackageAdvisory(
            package=package1,
            oid=advisory2,
            symbol=">=",
            is_vulnerable=lambda _: False,
        )

        self.assertEqual(hash(package_advisory1), hash(package_advisory1))
        self.assertEqual(hash(package_advisory1), hash(package_advisory3))
        self.assertNotEqual(hash(package_advisory1), hash(package_advisory2))
        self.assertNotEqual(hash(package_advisory3), hash(package_advisory2))
        self.assertNotEqual(hash(package_advisory1), hash(package_advisory4))
        self.assertNotEqual(hash(package_advisory2), hash(package_advisory4))


class PackageAdvisoriesTestCase(TestCase):
    def test_constructor(self):
        package_advisories = PackageAdvisories(PackageType.DEB)

        self.assertIsInstance(package_advisories.advisories, dict)
        self.assertEqual(len(package_advisories), 0)

    def test_add_advisory_for_package(self):
        package_advisories = PackageAdvisories(PackageType.RPM)
        package = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        advisory = "1.2.3.4.5"

        self.assertEqual(len(package_advisories), 0)

        package_advisories.add_advisory_for_package(package, advisory, None)

        self.assertEqual(len(package_advisories), 1)

    def test_default_is_vulnerable(self):
        package_advisories = PackageAdvisories(PackageType.RPM)
        package = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        advisory = "1.2.3.4.5"

        other = RPMPackage.from_full_name(
            "foo-1.2.4-3.aarch64",
        )
        package_advisories.add_advisory_for_package(package, advisory, None)
        advisories = package_advisories.get_package_advisories_for_package(
            other
        )
        self.assertEqual(1, len(advisories))
        for package_advisories in advisories.values():
            for adv in package_advisories:
                self.assertFalse(adv.is_vulnerable(other))

    def test_add_duplicate_advisory_for_package(self):
        package_advisories = PackageAdvisories(package_type=PackageType.RPM)
        package1 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        package2 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        advisory1 = "1.2.3.4.5"
        advisory2 = "1.2.3.4.5"

        self.assertEqual(len(package_advisories), 0)

        package_advisories.add_advisory_for_package(package1, advisory1, None)

        self.assertEqual(len(package_advisories), 1)

        package_advisories.add_advisory_for_package(package1, advisory1, None)

        self.assertEqual(len(package_advisories), 1)

        package_advisories.add_advisory_for_package(package1, advisory2, None)

        self.assertEqual(len(package_advisories), 1)

        package_advisories.add_advisory_for_package(package2, advisory1, None)

        self.assertEqual(len(package_advisories), 1)

        package_advisories.add_advisory_for_package(package2, advisory2, None)

    def test_get_package_advisories_for_package(self):
        package_advisories = PackageAdvisories(package_type=PackageType.RPM)
        package1 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        package2 = RPMPackage.from_full_name(
            "bar-1.2.3-3.aarch64",
        )
        advisory1 = "1.2.3.4.5"
        advisory2 = "1.2.3.4.6"

        self.assertEqual(len(package_advisories), 0)

        package_advisories.add_advisory_for_package(package1, advisory1, None)
        package_advisories.add_advisory_for_package(package1, advisory2, None)
        package_advisories.add_advisory_for_package(package2, advisory2, None)

        advisories1 = package_advisories.get_package_advisories_for_package(
            package1
        )
        advisories2 = package_advisories.get_package_advisories_for_package(
            package2
        )
        self.assertEqual(len(advisories1), 2)
        self.assertEqual(len(advisories2), 1)
