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

from unittest import TestCase

from notus.scanner.models.package import (
    Architecture,
    Package,
    parse_rpm_package,
)


def rpm_module_available():
    try:
        import rpm  # pylint: disable=unused-import,import-outside-toplevel

        return True
    except ModuleNotFoundError:
        return False


class ArchitectureTestCase(TestCase):
    def test_none(self):
        with self.assertRaises(ValueError):
            Architecture(None)

    def test_unknown(self):
        with self.assertRaises(ValueError):
            Architecture('foo')

    def test_known(self):
        self.assertEqual(Architecture.AARCH64, Architecture('aarch64'))
        self.assertEqual(Architecture.ARMV6L, Architecture('armv6l'))
        self.assertEqual(Architecture.ARMV7L, Architecture('armv7l'))
        self.assertEqual(Architecture.I386, Architecture('i386'))
        self.assertEqual(Architecture.I686, Architecture('i686'))
        self.assertEqual(Architecture.X86_64, Architecture('x86_64'))


class PackageTestCase(TestCase):
    def test_matching_hashes(self):
        package1 = Package(
            'foo-bar',
            '1.2.3',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.3-4.x86_64',
        )
        package2 = Package(
            'foo-bar',
            '1.2.3',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.3-4.x86_64',
        )

        self.assertEqual(hash(package1), hash(package2))

    def test_not_matching_hashes(self):
        package1 = Package(
            'foo-bar',
            '1.2.3',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.3-4.x86_64',
        )
        package2 = Package(
            'foo-bar',
            '1.2.4',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.4-4.x86_64',
        )

        self.assertNotEqual(hash(package1), hash(package2))

    def test_compare_gt(self):
        if not rpm_module_available():
            self.skipTest("No rpm module available skipping test")

        package1 = Package(
            'foo-bar',
            '1.2.3',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.3-4.x86_64',
        )
        package2 = Package(
            'foo-bar',
            '1.2.4',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.4-4.x86_64',
        )
        self.assertGreater(package2, package1)

        package2 = Package(
            'foo-bar',
            '1.2.3',
            '5',
            Architecture.X86_64,
            'foo-bar-1.2.3-5.x86_64',
        )
        self.assertGreater(package2, package1)

    def test_compare_gt_different_architecture(self):
        if not rpm_module_available():
            self.skipTest("No rpm module available skipping test")

        package1 = Package(
            'foo-bar',
            '1.2.3',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.3-4.x86_64',
        )
        package2 = Package(
            'foo-bar',
            '1.2.3',
            '4',
            Architecture.AARCH64,
            'foo-bar-1.2.3-4.aarch64',
        )
        self.assertFalse(package2 > package1)
        self.assertFalse(package1 > package2)

    def test_compare_less(self):
        if not rpm_module_available():
            self.skipTest("No rpm module available skipping test")

        package1 = Package(
            'foo-bar',
            '1.2.3',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.3-4.x86_64',
        )
        package2 = Package(
            'foo-bar',
            '1.2.4',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.4-4.x86_64',
        )
        self.assertLess(package1, package2)

        package2 = Package(
            'foo-bar',
            '1.2.3',
            '5',
            Architecture.X86_64,
            'foo-bar-1.2.3-5.x86_64',
        )
        self.assertLess(package1, package2)

    def test_compare_equal(self):
        package1 = Package(
            'foo-bar',
            '1.2.3',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.3-4.x86_64',
        )
        package2 = Package(
            'foo-bar',
            '1.2.3',
            '4',
            Architecture.X86_64,
            'foo-bar-1.2.3-4.x86_64',
        )

        self.assertEqual(package1, package2)


class ParseRpmPackageTestCase(TestCase):
    def test_none(self):
        self.assertIsNone(parse_rpm_package(None))

    def test_unknown_arch(self):
        package = parse_rpm_package('keyutils-1.5.8-3.foo')
        self.assertEqual(package.arch, Architecture.UNKNOWN)

    def test_no_arch(self):
        package = parse_rpm_package('keyutils-1.5.8-3')
        self.assertEqual(package.arch, Architecture.NOTSET)

    def test_parse_existing_euleros_packages(self):
        package = parse_rpm_package('mesa-libgbm-11.2.2-2.20160614.x86_64')
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, 'mesa-libgbm')
        self.assertEqual(package.version, '11.2.2')
        self.assertEqual(package.release, '2.20160614')
        self.assertEqual(
            package.full_name, 'mesa-libgbm-11.2.2-2.20160614.x86_64'
        )

        package = parse_rpm_package('keyutils-1.5.8-3.x86_64')
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, 'keyutils')
        self.assertEqual(package.version, '1.5.8')
        self.assertEqual(package.release, '3')
        self.assertEqual(package.full_name, 'keyutils-1.5.8-3.x86_64')

        package = parse_rpm_package('httpd-manual-2.4.6-45.0.1.4.h10.noarch')
        self.assertEqual(package.arch, Architecture.NOARCH)
        self.assertEqual(package.name, 'httpd-manual')
        self.assertEqual(package.version, '2.4.6')
        self.assertEqual(package.release, '45.0.1.4.h10')
        self.assertEqual(
            package.full_name, 'httpd-manual-2.4.6-45.0.1.4.h10.noarch'
        )

        package = parse_rpm_package('cups-libs-1.6.3-26.h1.x86_64')
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, 'cups-libs')
        self.assertEqual(package.version, '1.6.3')
        self.assertEqual(package.release, '26.h1')
        self.assertEqual(package.full_name, 'cups-libs-1.6.3-26.h1.x86_64')

        package = parse_rpm_package('GConf2-3.2.6-8.x86_64')
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, 'GConf2')
        self.assertEqual(package.version, '3.2.6')
        self.assertEqual(package.release, '8')
        self.assertEqual(package.full_name, 'GConf2-3.2.6-8.x86_64')

        package = parse_rpm_package('libtool-ltdl-2.4.2-21.x86_64')
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, 'libtool-ltdl')
        self.assertEqual(package.version, '2.4.2')
        self.assertEqual(package.release, '21')
        self.assertEqual(package.full_name, 'libtool-ltdl-2.4.2-21.x86_64')

        package = parse_rpm_package('microcode_ctl-2.1-22.6.h2.x86_64')
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, 'microcode_ctl')
        self.assertEqual(package.version, '2.1')
        self.assertEqual(package.release, '22.6.h2')
        self.assertEqual(package.full_name, 'microcode_ctl-2.1-22.6.h2.x86_64')

        package = parse_rpm_package('postgresql-libs-9.2.23-3.x86_64')
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, 'postgresql-libs')
        self.assertEqual(package.version, '9.2.23')
        self.assertEqual(package.release, '3')
        self.assertEqual(package.full_name, 'postgresql-libs-9.2.23-3.x86_64')

        package = parse_rpm_package('NetworkManager-1.8.0-9.h2.x86_64')
        self.assertEqual(package.arch, Architecture.X86_64)
        self.assertEqual(package.name, 'NetworkManager')
        self.assertEqual(package.version, '1.8.0')
        self.assertEqual(package.release, '9.h2')
        self.assertEqual(package.full_name, 'NetworkManager-1.8.0-9.h2.x86_64')

        package = parse_rpm_package('perl-Pod-Escapes-1.04-285.h2.noarch')
        self.assertEqual(package.arch, Architecture.NOARCH)
        self.assertEqual(package.name, 'perl-Pod-Escapes')
        self.assertEqual(package.version, '1.04')
        self.assertEqual(package.release, '285.h2')
        self.assertEqual(
            package.full_name, 'perl-Pod-Escapes-1.04-285.h2.noarch'
        )
