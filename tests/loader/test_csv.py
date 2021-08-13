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

from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase

from notus.scanner.errors import AdvisoriesLoadingError
from notus.scanner.loader.csv import CsvAdvisoriesLoader
from notus.scanner.models.package import parse_rpm_package

_here = Path(__file__).parent


class CsvAdvisoriesLoaderTestCase(TestCase):
    def test_unknown_file(self):
        loader = CsvAdvisoriesLoader(advisories_directory_path=_here)

        with self.assertRaises(AdvisoriesLoadingError):
            loader.load('foo')

    def test_empty_file(self):
        loader = CsvAdvisoriesLoader(advisories_directory_path=_here)

        advisories = loader.load('EmptyOS')
        self.assertEqual(len(advisories), 0)

    def test_example(self):
        loader = CsvAdvisoriesLoader(advisories_directory_path=_here)

        advisories = loader.load('EulerOS V2.0SP1')

        self.assertIsNotNone(advisories)
        self.assertEqual(len(advisories), 55)

        package1 = parse_rpm_package('openssh-6.6.1p1-25.4.h3.x86_64')
        package2 = parse_rpm_package('openssh-clients-6.6.1p1-25.4.h3.x86_64')

        package_advisories1 = advisories.get_package_advisories_for_package(
            package1
        )
        package_advisories2 = advisories.get_package_advisories_for_package(
            package2
        )

        self.assertEqual(len(package_advisories1), 1)
        self.assertEqual(len(package_advisories2), 1)

        # get first PackageAdvisory from the sets
        package_advisory1 = next(iter(package_advisories1))
        package_advisory2 = next(iter(package_advisories2))

        self.assertEqual(package_advisory1.advisory, package_advisory2.advisory)

        advisory = package_advisory1.advisory

        self.assertEqual(advisory.oid, '1.3.6.1.4.1.25623.1.1.2.2016.1008')
        self.assertEqual(
            advisory.title,
            # pylint: disable=line-too-long
            'Huawei EulerOS: Security Advisory for openssh (EulerOS-SA-2016-1008)',
        )
        self.assertEqual(advisory.advisory_id, 'EulerOS-SA-2016-1008')
        self.assertEqual(
            advisory.advisory_xref,
            # pylint: disable=line-too-long
            'https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1008',
        )
        self.assertEqual(advisory.cves, ['CVE-2016-1908', 'CVE-2016-3115'])
        self.assertEqual(advisory.xrefs, [])
        self.assertEqual(advisory.severity.origin, 'NVD')
        self.assertEqual(
            advisory.severity.cvss_v2, 'AV:N/AC:L/Au:N/C:P/I:P/A:P'
        )
        self.assertEqual(
            advisory.severity.cvss_v3,
            'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        )
        self.assertEqual(
            advisory.summary,
            # pylint: disable=line-too-long
            "The remote host is missing an update for the Huawei EulerOS 'openssh' package(s) announced via the EulerOS-SA-2016-1008 advisory.",
        )
        self.assertEqual(
            advisory.insight,
            # pylint: disable=line-too-long
            'It was discovered that the OpenSSH server did not sanitize data received in requests to enable X11 forwarding. An authenticated client with restricted SSH access could possibly use this flaw to bypass intended restrictions. (CVE-2016-3115)\n\n'
            # pylint: disable=line-too-long
            'An access flaw was discovered in OpenSSH, the OpenSSH client did not correctly handle failures to generate authentication cookies for untrusted X11 forwarding. A malicious or compromised remote X application could possibly use this flaw to establish a trusted connection to the local X server, even if only untrusted X11 forwarding was requested. (CVE-2016-1908)',
        )
        self.assertEqual(advisory.impact, '')
        self.assertEqual(
            advisory.creation_date,
            datetime(2021, 5, 27, 7, 3, 13, tzinfo=timezone.utc),
        )
        self.assertEqual(
            advisory.last_modification,
            datetime(2021, 7, 22, 2, 24, 2, tzinfo=timezone.utc),
        )
        self.assertEqual(
            advisory.severity.date,
            datetime(2018, 9, 11, 10, 29, tzinfo=timezone.utc),
        )
