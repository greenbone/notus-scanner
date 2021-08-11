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
from datetime import datetime
from unittest import TestCase

from notus.scanner.models.advisory import (
    Advisory,
    OperatingSystemAdvisories,
    PackageAdvisories,
    PackageAdvisory,
)
from notus.scanner.models.package import Architecture, Package


class AdvisoryTestCase(TestCase):
    def test_defaults(self):
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        advisory = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )

        self.assertEqual(advisory.oid, '1.2.3.4.5')
        self.assertEqual(advisory.title, 'Foo Bar')
        self.assertEqual(advisory.creation_date, creation_date)
        self.assertEqual(advisory.last_modification, last_modification)
        self.assertEqual(advisory.advisory_id, '1234')
        self.assertEqual(advisory.advisory_xref, 'http://foo/1234')
        self.assertEqual(advisory.severity_origin, 'foo')
        self.assertEqual(advisory.severity_date, severity_date)
        self.assertIsNone(advisory.severity_vector_v2)
        self.assertEqual(advisory.severity_vector_v3, cvss_v3)
        self.assertIsNone(advisory.summary)
        self.assertIsNone(advisory.insight)
        self.assertIsNone(advisory.affected)
        self.assertIsNone(advisory.impact)

        self.assertIsInstance(advisory.cve_list, list)
        self.assertEqual(len(advisory.cve_list), 0)
        self.assertIsInstance(advisory.xrefs, list)
        self.assertEqual(len(advisory.xrefs), 0)

    def test_hash(self):
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        advisory1 = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )
        advisory2 = Advisory(
            oid="1.2.3.4.5",
            title="Bar Foo",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="4321",
            advisory_xref="http://bar/4321",
            severity_origin="bar",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )
        advisory3 = Advisory(
            oid="1.2.3.4.6",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )

        self.assertEqual(hash(advisory1), hash(advisory2))
        self.assertNotEqual(hash(advisory1), hash(advisory3))

    def test_immutability(self):
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        advisory = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )

        with self.assertRaises(FrozenInstanceError):
            advisory.oid = '2.2.2.2.2'

        with self.assertRaises(FrozenInstanceError):
            advisory.title = 'Ipsum'

        with self.assertRaises(FrozenInstanceError):
            advisory.severity_date = datetime.now()


class PackageAdvisoryTestCase(TestCase):
    def test_constructor(self):
        package = Package(
            'foo', '1.2.3', '3', Architecture.AARCH64, 'foo-1.2.3-3.aarch64'
        )
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        advisory = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )

        package_advisory = PackageAdvisory(package=package, advisory=advisory)

        self.assertEqual(package_advisory.package, package)
        self.assertEqual(package_advisory.advisory, advisory)

    def test_immutability(self):
        package1 = Package(
            'foo', '1.2.3', '3', Architecture.AARCH64, 'foo-1.2.3-3.aarch64'
        )
        package2 = Package(
            'bar', '1.2.3', '3', Architecture.AARCH64, 'bar-1.2.3-3.aarch64'
        )
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        advisory1 = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )
        advisory2 = Advisory(
            oid="1.2.3.4.6",
            title="Bar Foo",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="4321",
            advisory_xref="http://bar/4321",
            severity_origin="bar",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )

        package_advisory = PackageAdvisory(package=package1, advisory=advisory1)

        with self.assertRaises(FrozenInstanceError):
            package_advisory.package = package2

        with self.assertRaises(FrozenInstanceError):
            package_advisory.advisory = advisory2

        self.assertEqual(package_advisory.package, package1)
        self.assertEqual(package_advisory.advisory, advisory1)

    def test_equal(self):
        package1 = Package(
            'foo', '1.2.3', '3', Architecture.AARCH64, 'foo-1.2.3-3.aarch64'
        )
        package2 = Package(
            'bar', '1.2.3', '3', Architecture.AARCH64, 'bar-1.2.3-3.aarch64'
        )
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        advisory1 = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )
        advisory2 = Advisory(
            oid="1.2.3.4.6",
            title="Bar Foo",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="4321",
            advisory_xref="http://bar/4321",
            severity_origin="bar",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
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
        package1 = Package(
            'foo', '1.2.3', '3', Architecture.AARCH64, 'foo-1.2.3-3.aarch64'
        )
        package2 = Package(
            'bar', '1.2.3', '3', Architecture.AARCH64, 'bar-1.2.3-3.aarch64'
        )
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        advisory1 = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )
        advisory2 = Advisory(
            oid="1.2.3.4.6",
            title="Bar Foo",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="4321",
            advisory_xref="http://bar/4321",
            severity_origin="bar",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
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
        self.assertEqual(len(package_advisories.advisories), 0)

    def test_add_advisory_for_package(self):
        package_advisories = PackageAdvisories()
        package = Package(
            'foo', '1.2.3', '3', Architecture.AARCH64, 'foo-1.2.3-3.aarch64'
        )
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        advisory = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )

        self.assertEqual(len(package_advisories.advisories), 0)

        package_advisories.add_advisory_for_package(package, advisory)

        self.assertEqual(len(package_advisories.advisories), 1)

    def test_add_duplicate_advisory_for_package(self):
        package_advisories = PackageAdvisories()
        package1 = Package(
            'foo', '1.2.3', '3', Architecture.AARCH64, 'foo-1.2.3-3.aarch64'
        )
        package2 = Package(
            'foo', '1.2.3', '3', Architecture.AARCH64, 'foo-1.2.3-3.aarch64'
        )
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        advisory1 = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )
        advisory2 = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )

        self.assertEqual(len(package_advisories.advisories), 0)

        package_advisories.add_advisory_for_package(package1, advisory1)

        self.assertEqual(len(package_advisories.advisories), 1)

        package_advisories.add_advisory_for_package(package1, advisory1)

        self.assertEqual(len(package_advisories.advisories), 1)

        package_advisories.add_advisory_for_package(package1, advisory2)

        self.assertEqual(len(package_advisories.advisories), 1)

        package_advisories.add_advisory_for_package(package2, advisory1)

        self.assertEqual(len(package_advisories.advisories), 1)

        package_advisories.add_advisory_for_package(package2, advisory2)

    def test_get_package_advisories_for_package(self):
        package_advisories = PackageAdvisories()
        package1 = Package(
            'foo', '1.2.3', '3', Architecture.AARCH64, 'foo-1.2.3-3.aarch64'
        )
        package2 = Package(
            'bar', '1.2.3', '3', Architecture.AARCH64, 'bar-1.2.3-3.aarch64'
        )
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        advisory1 = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )
        advisory2 = Advisory(
            oid="1.2.3.4.6",
            title="Bar Foo",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity_origin="foo",
            severity_date=severity_date,
            severity_vector_v3=cvss_v3,
        )

        self.assertEqual(len(package_advisories.advisories), 0)

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


class OperatingSystemAdvisoriesTestCase(TestCase):
    def test_constructor(self):
        os_advisories = OperatingSystemAdvisories()

        self.assertIsInstance(os_advisories.advisories, dict)
        self.assertEqual(len(os_advisories.advisories), 0)

    def test_immutability(self):
        os_advisories = OperatingSystemAdvisories()

        with self.assertRaises(FrozenInstanceError):
            os_advisories.advisories = dict()

    def test_set_package_advisory(self):
        os_advisories = OperatingSystemAdvisories()

        self.assertEqual(len(os_advisories.advisories), 0)

        advisories1 = PackageAdvisories()
        os_advisories.set_package_advisories('BarOS 1.0', advisories1)

        self.assertEqual(len(os_advisories.advisories), 1)

        advisories2 = PackageAdvisories()
        os_advisories.set_package_advisories('BarOS 1.0', advisories2)

        self.assertEqual(len(os_advisories.advisories), 1)

        advisories3 = PackageAdvisories()
        os_advisories.set_package_advisories('FooOS 2.0', advisories3)
        self.assertEqual(len(os_advisories.advisories), 2)

    def test_get_package_advisory(self):
        os_advisories = OperatingSystemAdvisories()

        self.assertEqual(len(os_advisories.advisories), 0)

        self.assertIsNone(os_advisories.get_package_advisories('BarOS 1.0'))

        advisories1 = PackageAdvisories()
        advisories2 = PackageAdvisories()
        os_advisories.set_package_advisories('BarOS 1.0', advisories1)
        os_advisories.set_package_advisories('FooOS 2.0', advisories2)

        self.assertEqual(
            os_advisories.get_package_advisories('BarOS 1.0'), advisories1
        )
        self.assertEqual(
            os_advisories.get_package_advisories('FooOS 2.0'), advisories2
        )
