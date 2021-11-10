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

from dataclasses import FrozenInstanceError
from unittest import TestCase

from notus.scanner.models.package import (
    AdvisoryReference,
    Architecture,
    OperatingSystemAdvisories,
    PackageAdvisories,
    PackageAdvisory,
    RPMPackage,
)


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


class RPMPackageTestCase(TestCase):
    def test_matching_hashes(self):
        """hashes for the same package should match"""
        package1 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )

        self.assertEqual(hash(package1), hash(package2))

    def test_not_matching_hashes(self):
        """hashes for different packages should not match"""
        package1 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="foo-bar",
            version="1.2.4",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.4-4.x86_64",
            full_version="1.2.4-4.x86_64",
        )

        self.assertNotEqual(hash(package1), hash(package2))

    def test_compare_gt(self):
        """packages should be comparable"""
        package1 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="foo-bar",
            version="1.2.4",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.4-4.x86_64",
            full_version="1.2.4-4.x86_64",
        )
        self.assertGreater(package2, package1)

        package2 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="5",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.3-5.x86_64",
            full_version="1.2.3-5.x86_64",
        )
        self.assertGreater(package2, package1)

    def test_compare_gt_different_architecture(self):
        """packages of different architecture should not be comparable"""
        package1 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="4",
            arch=Architecture.AARCH64,
            full_name="foo-bar-1.2.3-4.aarch64",
            full_version="1.2.3-4.aarch64",
        )
        self.assertFalse(package2 > package1)
        self.assertFalse(package1 > package2)

    def test_compare_less(self):
        """packages should be comparable"""
        package1 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="foo-bar",
            version="1.2.4",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.4-4.x86_64",
            full_version="1.2.4-4.x86_64",
        )
        self.assertLess(package1, package2)

        package2 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="5",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.3-5.x86_64",
            full_version="1.2.3-5.x86_64",
        )
        self.assertLess(package1, package2)

    def test_compare_equal(self):
        """packages with the same data should be equal"""
        package1 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="foo-bar",
            version="1.2.3",
            release="4",
            arch=Architecture.X86_64,
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )

        self.assertEqual(package1, package2)

    def test_from_full_name(self):
        """it should be possible to create packages via the full name"""
        self.assertIsNone(RPMPackage.from_full_name(None))

        package = RPMPackage.from_full_name("keyutils-1.5.8-3.foo")
        self.assertEqual(package.arch, Architecture.UNKNOWN)

        package = RPMPackage.from_full_name("keyutils-1.5.8-3")
        self.assertEqual(package.arch, Architecture.NOTSET)

        package = RPMPackage.from_full_name(
            "mesa-libgbm-11.2.2-2.20160614.x86_64"
        )
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, "mesa-libgbm")
        self.assertEqual(package.version, "11.2.2")
        self.assertEqual(package.release, "2.20160614")
        self.assertEqual(
            package.full_name, "mesa-libgbm-11.2.2-2.20160614.x86_64"
        )

        package = RPMPackage.from_full_name("keyutils-1.5.8-3.x86_64")
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, "keyutils")
        self.assertEqual(package.version, "1.5.8")
        self.assertEqual(package.release, "3")
        self.assertEqual(package.full_name, "keyutils-1.5.8-3.x86_64")

        package = RPMPackage.from_full_name(
            "httpd-manual-2.4.6-45.0.1.4.h10.noarch"
        )
        self.assertEqual(package.arch, Architecture.NOARCH)
        self.assertEqual(package.name, "httpd-manual")
        self.assertEqual(package.version, "2.4.6")
        self.assertEqual(package.release, "45.0.1.4.h10")
        self.assertEqual(
            package.full_name, "httpd-manual-2.4.6-45.0.1.4.h10.noarch"
        )

        package = RPMPackage.from_full_name("cups-libs-1.6.3-26.h1.x86_64")
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, "cups-libs")
        self.assertEqual(package.version, "1.6.3")
        self.assertEqual(package.release, "26.h1")
        self.assertEqual(package.full_name, "cups-libs-1.6.3-26.h1.x86_64")

        package = RPMPackage.from_full_name("GConf2-3.2.6-8.x86_64")
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, "GConf2")
        self.assertEqual(package.version, "3.2.6")
        self.assertEqual(package.release, "8")
        self.assertEqual(package.full_name, "GConf2-3.2.6-8.x86_64")

        package = RPMPackage.from_full_name("libtool-ltdl-2.4.2-21.x86_64")
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, "libtool-ltdl")
        self.assertEqual(package.version, "2.4.2")
        self.assertEqual(package.release, "21")
        self.assertEqual(package.full_name, "libtool-ltdl-2.4.2-21.x86_64")

        package = RPMPackage.from_full_name("microcode_ctl-2.1-22.6.h2.x86_64")
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, "microcode_ctl")
        self.assertEqual(package.version, "2.1")
        self.assertEqual(package.release, "22.6.h2")
        self.assertEqual(package.full_name, "microcode_ctl-2.1-22.6.h2.x86_64")

        package = RPMPackage.from_full_name("postgresql-libs-9.2.23-3.x86_64")
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, "postgresql-libs")
        self.assertEqual(package.version, "9.2.23")
        self.assertEqual(package.release, "3")
        self.assertEqual(package.full_name, "postgresql-libs-9.2.23-3.x86_64")

        package = RPMPackage.from_full_name("NetworkManager-1.8.0-9.h2.x86_64")
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, "NetworkManager")
        self.assertEqual(package.version, "1.8.0")
        self.assertEqual(package.release, "9.h2")
        self.assertEqual(package.full_name, "NetworkManager-1.8.0-9.h2.x86_64")

        package = RPMPackage.from_full_name(
            "perl-Pod-Escapes-1.04-285.h2.noarch"
        )
        self.assertEqual(package.arch, Architecture.NOARCH)
        self.assertEqual(package.name, "perl-Pod-Escapes")
        self.assertEqual(package.version, "1.04")
        self.assertEqual(package.release, "285.h2")
        self.assertEqual(
            package.full_name, "perl-Pod-Escapes-1.04-285.h2.noarch"
        )

        package = RPMPackage.from_full_name(" libtool-ltdl-2.4.2-21.x86_64\r\n")
        self.assertEqual(package.arch, Architecture.X86_64)

    def test_from_name_and_full_version(self):
        """it should be possible to create packages from name and full
        version"""
        self.assertIsNone(RPMPackage.from_name_and_full_version(None, None))

        package = RPMPackage.from_name_and_full_version(
            "cups-libs", "1.6.3-26.h1.x86_64"
        )
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, "cups-libs")
        self.assertEqual(package.version, "1.6.3")
        self.assertEqual(package.release, "26.h1")
        self.assertEqual(package.full_name, "cups-libs-1.6.3-26.h1.x86_64")


class OperatingSystemAdvisoriesTestCase(TestCase):
    def test_constructor(self):
        os_advisories = OperatingSystemAdvisories()

        self.assertIsInstance(os_advisories.advisories, dict)
        self.assertEqual(len(os_advisories), 0)

    def test_immutability(self):
        os_advisories = OperatingSystemAdvisories()

        with self.assertRaises(FrozenInstanceError):
            os_advisories.advisories = dict()

    def test_set_package_advisory(self):
        os_advisories = OperatingSystemAdvisories()

        self.assertEqual(len(os_advisories), 0)

        advisories1 = PackageAdvisories()
        os_advisories.set_package_advisories("BarOS 1.0", advisories1)

        self.assertEqual(len(os_advisories), 1)

        advisories2 = PackageAdvisories()
        os_advisories.set_package_advisories("BarOS 1.0", advisories2)

        self.assertEqual(len(os_advisories), 1)

        advisories3 = PackageAdvisories()
        os_advisories.set_package_advisories("FooOS 2.0", advisories3)
        self.assertEqual(len(os_advisories), 2)

    def test_get_package_advisory(self):
        os_advisories = OperatingSystemAdvisories()

        self.assertEqual(len(os_advisories), 0)

        advisories = os_advisories.get_package_advisories("BarOS 1.0")
        self.assertEqual(len(advisories), 0)

        advisories1 = PackageAdvisories()
        advisories2 = PackageAdvisories()
        os_advisories.set_package_advisories("BarOS 1.0", advisories1)
        os_advisories.set_package_advisories("FooOS 2.0", advisories2)

        self.assertEqual(
            os_advisories.get_package_advisories("BarOS 1.0"), advisories1
        )
        self.assertEqual(
            os_advisories.get_package_advisories("FooOS 2.0"), advisories2
        )


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
        package_advisories = PackageAdvisories()

        self.assertIsInstance(package_advisories.advisories, dict)
        self.assertEqual(len(package_advisories), 0)

    def test_add_advisory_for_package(self):
        package_advisories = PackageAdvisories()
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
        package_advisories = PackageAdvisories()
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
        package_advisories = PackageAdvisories()
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
