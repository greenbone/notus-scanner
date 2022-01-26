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

from notus.scanner.models.packages.package import (
    Package,
    AdvisoryReference,
    Architecture,
    PackageAdvisories,
    PackageAdvisory,
    PackageType,
)
from notus.scanner.models.packages.rpm import RPMPackage
from notus.scanner.models.packages.deb import DEBPackage


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
            arch=Architecture.X86_64,
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


class ArchitectureTestCase(TestCase):
    def test_none(self):
        with self.assertRaises(ValueError):
            Architecture(None)

    def test_unknown(self):
        with self.assertRaises(ValueError):
            Architecture("foo")

    def test_known(self):
        self.assertEqual(Architecture.AARCH64, Architecture("aarch64"))
        self.assertEqual(Architecture.ARMV6L, Architecture("armv6l"))
        self.assertEqual(Architecture.ARMV7L, Architecture("armv7l"))
        self.assertEqual(Architecture.I386, Architecture("i386"))
        self.assertEqual(Architecture.I686, Architecture("i686"))
        self.assertEqual(Architecture.X86_64, Architecture("x86_64"))


class PackageAdvisoryTestCase(TestCase):
    def test_constructor(self):
        package = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        advisory = AdvisoryReference(
            oid="1.2.3.4.5",
        )

        package_advisory = PackageAdvisory(package=package, advisory=advisory)

        self.assertEqual(package_advisory.package, package)
        self.assertEqual(package_advisory.advisory, advisory)

    def test_immutability(self):
        package1 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        package2 = RPMPackage.from_full_name(
            "bar-1.2.3-3.aarch64",
        )
        advisory1 = AdvisoryReference(
            oid="1.2.3.4.5",
        )
        advisory2 = AdvisoryReference(
            oid="1.2.3.4.6",
        )

        package_advisory = PackageAdvisory(package=package1, advisory=advisory1)

        with self.assertRaises(FrozenInstanceError):
            package_advisory.package = package2

        with self.assertRaises(FrozenInstanceError):
            package_advisory.advisory = advisory2

        self.assertEqual(package_advisory.package, package1)
        self.assertEqual(package_advisory.advisory, advisory1)

    def test_equal(self):
        package1 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        package2 = RPMPackage.from_full_name(
            "bar-1.2.3-3.aarch64",
        )
        advisory1 = AdvisoryReference(
            oid="1.2.3.4.5",
        )
        advisory2 = AdvisoryReference(
            oid="1.2.3.4.6",
        )

        package_advisory1 = PackageAdvisory(
            package=package1, advisory=advisory1
        )
        package_advisory2 = PackageAdvisory(
            package=package2, advisory=advisory2
        )
        package_advisory3 = PackageAdvisory(
            package=package1, advisory=advisory1
        )
        package_advisory4 = PackageAdvisory(
            package=package1, advisory=advisory2
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
        advisory1 = AdvisoryReference(
            oid="1.2.3.4.5",
        )
        advisory2 = AdvisoryReference(
            oid="1.2.3.4.6",
        )

        package_advisory1 = PackageAdvisory(
            package=package1, advisory=advisory1
        )
        package_advisory2 = PackageAdvisory(
            package=package2, advisory=advisory2
        )
        package_advisory3 = PackageAdvisory(
            package=package1, advisory=advisory1
        )
        package_advisory4 = PackageAdvisory(
            package=package1, advisory=advisory2
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
        advisory = AdvisoryReference(
            oid="1.2.3.4.5",
        )

        self.assertEqual(len(package_advisories), 0)

        package_advisories.add_advisory_for_package(package, advisory)

        self.assertEqual(len(package_advisories), 1)

    def test_add_duplicate_advisory_for_package(self):
        package_advisories = PackageAdvisories(package_type=PackageType.RPM)
        package1 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        package2 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        advisory1 = AdvisoryReference(
            oid="1.2.3.4.5",
        )
        advisory2 = AdvisoryReference(
            oid="1.2.3.4.5",
        )

        self.assertEqual(len(package_advisories), 0)

        package_advisories.add_advisory_for_package(package1, advisory1)

        self.assertEqual(len(package_advisories), 1)

        package_advisories.add_advisory_for_package(package1, advisory1)

        self.assertEqual(len(package_advisories), 1)

        package_advisories.add_advisory_for_package(package1, advisory2)

        self.assertEqual(len(package_advisories), 1)

        package_advisories.add_advisory_for_package(package2, advisory1)

        self.assertEqual(len(package_advisories), 1)

        package_advisories.add_advisory_for_package(package2, advisory2)

    def test_get_package_advisories_for_package(self):
        package_advisories = PackageAdvisories(package_type=PackageType.RPM)
        package1 = RPMPackage.from_full_name(
            "foo-1.2.3-3.aarch64",
        )
        package2 = RPMPackage.from_full_name(
            "bar-1.2.3-3.aarch64",
        )
        advisory1 = AdvisoryReference(
            oid="1.2.3.4.5",
        )
        advisory2 = AdvisoryReference(
            oid="1.2.3.4.6",
        )

        self.assertEqual(len(package_advisories), 0)

        package_advisories.add_advisory_for_package(package1, advisory1)
        package_advisories.add_advisory_for_package(package1, advisory2)
        package_advisories.add_advisory_for_package(package2, advisory2)

        advisories1 = package_advisories.get_package_advisories_for_package(
            package1
        )
        advisories2 = package_advisories.get_package_advisories_for_package(
            package2
        )
        self.assertEqual(len(advisories1), 2)
        self.assertEqual(len(advisories2), 1)
