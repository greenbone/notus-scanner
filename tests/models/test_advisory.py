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
from datetime import datetime
from unittest import TestCase

from notus.scanner.models.advisory import (
    Advisory,
    Severity,
)


class AdvisoryTestCase(TestCase):
    def test_defaults(self):
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        severity = Severity(
            origin="foo",
            date=severity_date,
            cvss_v3=cvss_v3,
        )
        advisory = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity=severity,
        )

        self.assertEqual(advisory.oid, "1.2.3.4.5")
        self.assertEqual(advisory.title, "Foo Bar")
        self.assertEqual(advisory.creation_date, creation_date)
        self.assertEqual(advisory.last_modification, last_modification)
        self.assertEqual(advisory.advisory_id, "1234")
        self.assertEqual(advisory.advisory_xref, "http://foo/1234")
        self.assertEqual(advisory.severity.origin, "foo")
        self.assertEqual(advisory.severity.date, severity_date)
        self.assertIsNone(advisory.severity.cvss_v2)
        self.assertEqual(advisory.severity.cvss_v3, cvss_v3)
        self.assertIsNone(advisory.summary)
        self.assertIsNone(advisory.insight)
        self.assertIsNone(advisory.affected)
        self.assertIsNone(advisory.impact)

        self.assertIsInstance(advisory.cves, list)
        self.assertEqual(len(advisory.cves), 0)
        self.assertIsInstance(advisory.xrefs, list)
        self.assertEqual(len(advisory.xrefs), 0)

    def test_hash(self):
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        severity = Severity(
            origin="foo",
            date=severity_date,
            cvss_v3=cvss_v3,
        )
        advisory1 = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity=severity,
        )
        advisory2 = Advisory(
            oid="1.2.3.4.5",
            title="Bar Foo",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="4321",
            advisory_xref="http://bar/4321",
            severity=severity,
        )
        advisory3 = Advisory(
            oid="1.2.3.4.6",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity=severity,
        )

        self.assertEqual(hash(advisory1), hash(advisory2))
        self.assertNotEqual(hash(advisory1), hash(advisory3))

    def test_immutability(self):
        severity_date = datetime(year=2021, month=1, day=2, hour=11, minute=11)
        creation_date = datetime(year=2021, month=3, day=21, hour=10, minute=0)
        last_modification = datetime.now()
        cvss_v3 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        severity = Severity(
            origin="foo",
            date=severity_date,
            cvss_v3=cvss_v3,
        )
        advisory = Advisory(
            oid="1.2.3.4.5",
            title="Foo Bar",
            creation_date=creation_date,
            last_modification=last_modification,
            advisory_id="1234",
            advisory_xref="http://foo/1234",
            severity=severity,
        )

        with self.assertRaises(FrozenInstanceError):
            advisory.oid = "2.2.2.2.2"

        with self.assertRaises(FrozenInstanceError):
            advisory.title = "Ipsum"

        with self.assertRaises(FrozenInstanceError):
            advisory.last_modification = datetime.now()
