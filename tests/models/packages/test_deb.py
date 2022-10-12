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

from notus.scanner.models.packages.deb import DEBPackage


class DEBPackageTestCase(TestCase):
    def test_compare_gt(self):
        """packages should be comparable"""
        package1 = DEBPackage(
            name="foo-bar",
            epoch="1",
            upstream_version="1.2.3",
            debian_revision="4",
            full_name="foo-bar-1:1.2.3-4",
            full_version="1:1.2.3-4",
        )
        package2 = DEBPackage(
            name="foo-bar",
            epoch="1",
            upstream_version="1.2.4",
            debian_revision="4",
            full_name="foo-bar-1:1.2.4-4",
            full_version="1:1.2.4-4",
        )
        self.assertGreater(package2, package1)

        package2 = DEBPackage(
            name="foo-bar",
            epoch="1",
            upstream_version="1.2.3",
            debian_revision="5",
            full_name="foo-bar-1:1.2.3-5",
            full_version="1:1.2.3-5",
        )
        self.assertGreater(package2, package1)

    def test_compare_gt_different_name(self):
        """different packagtes should not be comparable"""
        package1 = DEBPackage(
            name="foo",
            epoch="1",
            upstream_version="1.2.3",
            debian_revision="4",
            full_name="foo-1:1.2.3-4",
            full_version="1:1.2.3-4",
        )
        package2 = DEBPackage(
            name="bar",
            epoch="1",
            upstream_version="1.2.3",
            debian_revision="4",
            full_name="bar-1:1.2.3-4",
            full_version="1:1.2.3-4",
        )
        self.assertFalse(package2 > package1)
        self.assertFalse(package1 > package2)

    def test_compare_less(self):
        """packages should be comparable"""
        package1 = DEBPackage(
            name="foo-bar",
            epoch="1",
            upstream_version="1.2.3",
            debian_revision="4",
            full_name="foo-bar-1:1.2.3-4",
            full_version="1:1.2.3-4",
        )
        package2 = DEBPackage(
            name="foo-bar",
            epoch="1",
            upstream_version="1.2.4",
            debian_revision="4",
            full_name="foo-bar-1:1.2.4-4",
            full_version="1:1.2.4-4",
        )
        self.assertLess(package1, package2)

        package2 = DEBPackage(
            name="foo-bar",
            epoch="1",
            upstream_version="1.2.3",
            debian_revision="5",
            full_name="foo-bar-1.2.3-5:1",
            full_version="1:1.2.3-5",
        )
        self.assertLess(package1, package2)

        package2 = DEBPackage(
            name="foo-bar",
            epoch="1",
            upstream_version="1.2.3~rc",
            debian_revision="4",
            full_name="foo-bar-1:1.2.3~rc-4",
            full_version="1:1.2.3~rc-4",
        )
        self.assertLess(package2, package1)

    def test_compare_equal(self):
        """packages with the same data should be equal"""
        package1 = DEBPackage(
            name="foo-bar",
            epoch="1",
            upstream_version="1.2.3",
            debian_revision="4",
            full_name="foo-bar-1:1.2.3-4",
            full_version="1:1.2.3-4",
        )
        package2 = DEBPackage(
            name="foo-bar",
            epoch="1",
            upstream_version="1.2.3",
            debian_revision="4",
            full_name="foo-bar-1:1.2.3-4",
            full_version="1:1.2.3-4",
        )

        self.assertEqual(package1, package2)

    def test_from_full_name(self):
        """it should be possible to create packages via the full name"""
        self.assertIsNone(DEBPackage.from_full_name(None))

        package = DEBPackage.from_full_name("mesa-libgbm-2:11.2.2-2.20160614")
        self.assertEqual(package.name, "mesa-libgbm")
        self.assertEqual(package.epoch, "2")
        self.assertEqual(package.upstream_version, "11.2.2")
        self.assertEqual(package.debian_revision, "2.20160614")
        self.assertEqual(package.full_name, "mesa-libgbm-2:11.2.2-2.20160614")
        self.assertEqual(package.full_version, "2:11.2.2-2.20160614")

        package = DEBPackage.from_full_name("keyutils-1.5.8-3")
        self.assertEqual(package.name, "keyutils")
        self.assertEqual(package.epoch, "0")
        self.assertEqual(package.upstream_version, "1.5.8")
        self.assertEqual(package.debian_revision, "3")
        self.assertEqual(package.full_name, "keyutils-1.5.8-3")
        self.assertEqual(package.full_version, "1.5.8-3")

        package = DEBPackage.from_full_name("httpd-manual-1:2.4.6-45.0.1.4.h10")
        self.assertEqual(package.name, "httpd-manual")
        self.assertEqual(package.epoch, "1")
        self.assertEqual(package.upstream_version, "2.4.6")
        self.assertEqual(package.debian_revision, "45.0.1.4.h10")
        self.assertEqual(package.full_name, "httpd-manual-1:2.4.6-45.0.1.4.h10")

        package = DEBPackage.from_full_name("libzstd1-1.3.8+dfsg-3+deb10u2")
        self.assertEqual(package.name, "libzstd1")
        self.assertEqual(package.epoch, "0")
        self.assertEqual(package.upstream_version, "1.3.8+dfsg")
        self.assertEqual(package.debian_revision, "3+deb10u2")
        self.assertEqual(package.full_name, "libzstd1-1.3.8+dfsg-3+deb10u2")

        package = DEBPackage.from_full_name(
            "xserver-xorg-video-intel-2:2.99.917+git20180925-2"
        )
        self.assertEqual(package.name, "xserver-xorg-video-intel")
        self.assertEqual(package.epoch, "2")
        self.assertEqual(package.upstream_version, "2.99.917+git20180925")
        self.assertEqual(package.debian_revision, "2")
        self.assertEqual(
            package.full_name,
            "xserver-xorg-video-intel-2:2.99.917+git20180925-2",
        )

        package = DEBPackage.from_full_name("ucf-3.0038+nmu1")
        self.assertEqual(package.name, "ucf")
        self.assertEqual(package.epoch, "0")
        self.assertEqual(package.upstream_version, "3.0038+nmu1")
        self.assertEqual(package.debian_revision, "")
        self.assertEqual(package.full_name, "ucf-3.0038+nmu1")

        package = DEBPackage.from_full_name("apport-symptoms-020")
        self.assertEqual(package.name, "apport-symptoms")
        self.assertEqual(package.epoch, "0")
        self.assertEqual(package.upstream_version, "020")
        self.assertEqual(package.debian_revision, "")
        self.assertEqual(package.full_name, "apport-symptoms-020")

    def test_from_name_and_full_version(self):
        """it should be possible to create packages from name and full
        version"""
        self.assertIsNone(DEBPackage.from_name_and_full_version(None, None))

        package = DEBPackage.from_name_and_full_version(
            "mesa-libgbm", "2:11.2.2-2.20160614"
        )
        self.assertEqual(package.name, "mesa-libgbm")
        self.assertEqual(package.epoch, "2")
        self.assertEqual(package.upstream_version, "11.2.2")
        self.assertEqual(package.debian_revision, "2.20160614")
        self.assertEqual(package.full_name, "mesa-libgbm-2:11.2.2-2.20160614")
        self.assertEqual(package.full_version, "2:11.2.2-2.20160614")

        package = DEBPackage.from_name_and_full_version(
            "mesa-libgbm", "2:11.2.2"
        )
        self.assertEqual(package.name, "mesa-libgbm")
        self.assertEqual(package.epoch, "2")
        self.assertEqual(package.upstream_version, "11.2.2")
        self.assertEqual(package.debian_revision, "")
        self.assertEqual(package.full_name, "mesa-libgbm-2:11.2.2")
        self.assertEqual(package.full_version, "2:11.2.2")

        package = DEBPackage.from_name_and_full_version("mesa-libgbm", "11.2.2")
        self.assertEqual(package.name, "mesa-libgbm")
        self.assertEqual(package.epoch, "0")
        self.assertEqual(package.upstream_version, "11.2.2")
        self.assertEqual(package.debian_revision, "")
        self.assertEqual(package.full_name, "mesa-libgbm-11.2.2")
        self.assertEqual(package.full_version, "11.2.2")

        package = DEBPackage.from_name_and_full_version(
            "mesa-libgbm", "11.2.2-2.20160614"
        )
        self.assertEqual(package.name, "mesa-libgbm")
        self.assertEqual(package.epoch, "0")
        self.assertEqual(package.upstream_version, "11.2.2")
        self.assertEqual(package.debian_revision, "2.20160614")
        self.assertEqual(package.full_name, "mesa-libgbm-11.2.2-2.20160614")
        self.assertEqual(package.full_version, "11.2.2-2.20160614")
