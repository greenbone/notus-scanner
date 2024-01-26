# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from unittest import TestCase

from notus.scanner.models.packages.rpm import RPMPackage


class RPMPackageTestCase(TestCase):
    def test_compare_gt(self):
        """packages should be comparable"""
        package1 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.3",
            release="4",
            arch="x86_64",
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.4",
            release="4",
            arch="x86_64",
            full_name="foo-bar-1.2.4-4.x86_64",
            full_version="1.2.4-4.x86_64",
        )
        self.assertGreater(package2, package1)

        package2 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.3",
            release="5",
            arch="x86_64",
            full_name="foo-bar-1.2.3-5.x86_64",
            full_version="1.2.3-5.x86_64",
        )
        self.assertGreater(package2, package1)

    def test_compare_gt_different_architecture(self):
        """packages of different architecture should not be comparable"""
        package1 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.3",
            release="4",
            arch="x86_64",
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.3",
            release="4",
            arch="aarch64",
            full_name="foo-bar-1.2.3-4.aarch64",
            full_version="1.2.3-4.aarch64",
        )
        package3 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.4",
            release="4",
            arch="aarch64",
            full_name="foo-bar-1.2.4-4.aarch64",
            full_version="1.2.4-4.aarch64",
        )
        package4 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.3",
            release="5",
            arch="aarch64",
            full_name="foo-bar-1.2.3-5.aarch64",
            full_version="1.2.3-5.aarch64",
        )
        self.assertFalse(package2 > package1)
        self.assertFalse(package1 > package2)
        self.assertFalse(package3 > package1)
        self.assertFalse(package1 > package3)
        self.assertFalse(package4 > package1)
        self.assertFalse(package1 > package4)

    def test_compare_gt_different_epoch(self):
        """packages from different architectures should not be comparable"""
        package1 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.3",
            release="4",
            arch="x86_64",
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.3",
            release="4",
            arch="aarch64",
            full_name="foo-bar-1.2.3-4.aarch64",
            full_version="1.2.3-4.aarch64",
        )
        self.assertFalse(package1 > package2)
        self.assertFalse(package2 > package1)

    def test_compare_gt_different_name(self):
        """different packages should not be comparable"""
        package1 = RPMPackage(
            name="foo",
            epoch="0",
            version="1.2.3",
            release="4",
            arch="x86_64",
            full_name="foo-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="bar",
            epoch="0",
            version="1.2.3",
            release="4",
            arch="x86_64",
            full_name="bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        self.assertFalse(package2 > package1)
        self.assertFalse(package1 > package2)

    def test_compare_less(self):
        """packages should be comparable"""
        package1 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.3",
            release="4",
            arch="x86_64",
            full_name="foo-bar-1.2.3-4.x86_64",
            full_version="1.2.3-4.x86_64",
        )
        package2 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.4",
            release="4",
            arch="x86_64",
            full_name="foo-bar-1.2.4-4.x86_64",
            full_version="1.2.4-4.x86_64",
        )
        self.assertLess(package1, package2)

        package2 = RPMPackage(
            name="foo-bar",
            epoch="0",
            version="1.2.3",
            release="5",
            arch="x86_64",
            full_name="foo-bar-1.2.3-5.x86_64",
            full_version="1.2.3-5.x86_64",
        )
        self.assertLess(package1, package2)

    def test_compare_equal(self):
        """packages with the same data should be equal"""
        package1 = RPMPackage(
            name="docker-engine",
            epoch="0",
            version="18.09.0.200",
            release="200.h47.28.15.eulerosv2r10",
            arch="x86_64",
            full_name=(
                "docker-engine-18.09.0.200-200.h47.28.15.eulerosv2r10.x86_64"
            ),
            full_version="18.09.0.200-200.h47.28.15.eulerosv2r10.x86_64",
        )
        package2 = RPMPackage(
            name="docker-engine",
            epoch="1",
            version="18.09.0",
            release="200.h62.33.19.eulerosv2r10",
            arch="x86_64",
            full_name=(
                "docker-engine-1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64"
            ),
            full_version="1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64",
        )

        self.assertTrue(package2 > package1)

    def test_from_full_name(self):
        """it should be possible to create packages via the full name"""
        self.assertIsNone(RPMPackage.from_full_name(None))

        package = RPMPackage.from_full_name("keyutils-1.5.8-3.amd64")
        self.assertEqual(package.arch, "amd64")

        package = RPMPackage.from_full_name("keyutils-1.5.8-3.noarch")
        self.assertEqual(package.arch, "noarch")

        package = RPMPackage.from_full_name(
            "mesa-libgbm-11.2.2-2.20160614.x86_64"
        )

        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "mesa-libgbm")
        self.assertEqual(package.version, "11.2.2")
        self.assertEqual(package.release, "2.20160614")
        self.assertEqual(
            package.full_name, "mesa-libgbm-11.2.2-2.20160614.x86_64"
        )

        package = RPMPackage.from_full_name("keyutils-1.5.8-3.x86_64")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "keyutils")
        self.assertEqual(package.version, "1.5.8")
        self.assertEqual(package.release, "3")
        self.assertEqual(package.full_name, "keyutils-1.5.8-3.x86_64")

        package = RPMPackage.from_full_name(
            "httpd-manual-2.4.6-45.0.1.4.h10.noarch"
        )
        self.assertEqual(package.arch, "noarch")
        self.assertEqual(package.name, "httpd-manual")
        self.assertEqual(package.version, "2.4.6")
        self.assertEqual(package.release, "45.0.1.4.h10")
        self.assertEqual(
            package.full_name, "httpd-manual-2.4.6-45.0.1.4.h10.noarch"
        )

        package = RPMPackage.from_full_name("cups-libs-1.6.3-26.h1.x86_64")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "cups-libs")
        self.assertEqual(package.version, "1.6.3")
        self.assertEqual(package.release, "26.h1")
        self.assertEqual(package.full_name, "cups-libs-1.6.3-26.h1.x86_64")

        package = RPMPackage.from_full_name("GConf2-3.2.6-8.x86_64")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "GConf2")
        self.assertEqual(package.version, "3.2.6")
        self.assertEqual(package.release, "8")
        self.assertEqual(package.full_name, "GConf2-3.2.6-8.x86_64")

        package = RPMPackage.from_full_name("libtool-ltdl-2.4.2-21.x86_64")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "libtool-ltdl")
        self.assertEqual(package.version, "2.4.2")
        self.assertEqual(package.release, "21")
        self.assertEqual(package.full_name, "libtool-ltdl-2.4.2-21.x86_64")

        package = RPMPackage.from_full_name("microcode_ctl-2.1-22.6.h2.x86_64")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "microcode_ctl")
        self.assertEqual(package.version, "2.1")
        self.assertEqual(package.release, "22.6.h2")
        self.assertEqual(package.full_name, "microcode_ctl-2.1-22.6.h2.x86_64")

        package = RPMPackage.from_full_name("postgresql-libs-9.2.23-3.x86_64")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "postgresql-libs")
        self.assertEqual(package.version, "9.2.23")
        self.assertEqual(package.release, "3")
        self.assertEqual(package.full_name, "postgresql-libs-9.2.23-3.x86_64")

        package = RPMPackage.from_full_name("NetworkManager-1.8.0-9.h2.x86_64")
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "NetworkManager")
        self.assertEqual(package.version, "1.8.0")
        self.assertEqual(package.release, "9.h2")
        self.assertEqual(package.full_name, "NetworkManager-1.8.0-9.h2.x86_64")

        package = RPMPackage.from_full_name(
            "perl-Pod-Escapes-1.04-285.h2.noarch"
        )
        self.assertEqual(package.arch, "noarch")
        self.assertEqual(package.name, "perl-Pod-Escapes")
        self.assertEqual(package.version, "1.04")
        self.assertEqual(package.release, "285.h2")
        self.assertEqual(
            package.full_name, "perl-Pod-Escapes-1.04-285.h2.noarch"
        )

        package = RPMPackage.from_full_name(" libtool-ltdl-2.4.2-21.x86_64\r\n")
        self.assertEqual(package.arch, "x86_64")

        package = RPMPackage.from_full_name(
            "docker-engine-1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64"
        )
        self.assertEqual(
            package.full_name,
            "docker-engine-1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64",
        )
        self.assertEqual(
            package.full_version, "1:18.09.0-200.h62.33.19.eulerosv2r10.x86_64"
        )
        self.assertEqual(package.epoch, 1)
        self.assertEqual(package.version, "18.09.0")
        self.assertEqual(package.release, "200.h62.33.19.eulerosv2r10")
        self.assertEqual(package.arch, "x86_64")

    def test_from_name_and_full_version(self):
        """it should be possible to create packages from name and full
        version"""
        self.assertIsNone(RPMPackage.from_name_and_full_version(None, None))

        package = RPMPackage.from_name_and_full_version(
            "cups-libs", "1.6.3-26.h1.x86_64"
        )
        self.assertEqual(package.arch, "x86_64")
        self.assertEqual(package.name, "cups-libs")
        self.assertEqual(package.version, "1.6.3")
        self.assertEqual(package.release, "26.h1")
        self.assertEqual(package.full_name, "cups-libs-1.6.3-26.h1.x86_64")

    def test_exceptions(self):
        """tests for the exceptions _fips and .ksplice"""
        package1 = RPMPackage.from_full_name("gnutls-3.6.16-4.el8.x86_64")
        package2 = RPMPackage.from_full_name(
            "gnutls-3.6.16-4.0.1.el8_fips.x86_64"
        )

        self.assertFalse(package1 > package2)
        self.assertFalse(package2 > package1)

        package1 = RPMPackage.from_full_name("gnutls-3.6.16-4.el8_fips.x86_64")

        self.assertTrue(package2 > package1)

        package1 = RPMPackage.from_full_name(
            "openssl-libs-1.0.2k-24.0.3.el7_8.x86_64"
        )
        package2 = RPMPackage.from_full_name(
            "openssl-libs-1.0.2k-24.0.3.ksplice1.el7_9.x86_64"
        )

        self.assertFalse(package1 > package2)
        self.assertFalse(package2 > package1)

        package1 = RPMPackage.from_full_name(
            "openssl-libs-1.0.2k-24.0.3.ksplice1.el7_8.x86_64"
        )

        self.assertTrue(package2 > package1)
