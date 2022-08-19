# slightly adjusted from https://github.com/ihiji/version_utils
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
slackware module for version_utils

Contains dpkg parsing and comparison operations for version_utils.
Public methods include:

    * :any:`compare_packages`: compare two dpkg package strings, e.g.
      ``gcc-4.4.7-16.el6.x86_64`` and ``gcc-4.4.7-17.el6.x86_64``
    * :any:`compare_versions`: compare two dpkg version strings (the
      bit between the dashes in an dpkg package string)
    * :any:`package`: parse an dpkg package string to get name, epoch,
      version, release, and architecture information. Returns as a
      :any:`common.Package` object.
"""

import logging
import re
from dataclasses import dataclass
from packaging.version import parse

from .package import Architecture, Package, PackageComparision

_slack_compile = re.compile(r"(..*)-(..*)-(..*)-(\d)(?:_slack(..*))?")
_slack_compile_version = re.compile(r"(..*)-(..*)-(\d)(?:_slack(..*))?")


logger = logging.getLogger(__name__)


@dataclass
class SlackPackage(Package):
    """Represents a skackware based package"""

    build: str
    target: str
    version: str
    arch: str

    __hash__ = Package.__hash__

    def _compare(self, other: "SlackPackage") -> PackageComparision:
        if self.arch != other.arch:
            return PackageComparision.NOT_COMPARABLE

        if self.full_version == other.full_version:
            return PackageComparision.EQUAL

        a_version = parse(self.version)
        b_version = parse(other.version)

        if a_version != b_version:
            return (
                PackageComparision.A_NEWER
                if a_version > b_version
                else PackageComparision.B_NEWER
            )

        a_target = parse(self.target)
        b_target = parse(other.target)

        if a_target and b_target and a_target != b_target:
            return (
                PackageComparision.A_NEWER
                if a_target > b_target
                else PackageComparision.B_NEWER
            )

        a_build = parse(self.build)
        b_build = parse(other.build)

        if a_build != b_build:
            return (
                PackageComparision.A_NEWER
                if a_build > b_build
                else PackageComparision.B_NEWER
            )

    @staticmethod
    def from_full_name(full_name: str):
        if not full_name:
            return None

        full_name = full_name.strip()
        try:
            name, version, architecture, build, target = _slack_compile.match(
                full_name
            ).groups()
        except AttributeError:
            logger.warning(
                "The slack package %s could not be parsed", full_name
            )
            return None

        try:
            arch = Architecture(architecture)
        except ValueError:
            arch = Architecture.UNKNOWN

        full_version = f"{version}-{arch.value}-{build}"

        if target:
            full_version = f"{full_version}_slack{target}"

        return SlackPackage(
            name=name,
            arch=arch,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
            build=build,
            target=target or "",
            version=version,
        )

    @staticmethod
    def from_name_and_full_version(name: str, full_version: str):
        if not name or not full_version:
            return None
        name = name.strip()
        full_version = full_version.strip()
        try:
            version, architecture, build, target = _slack_compile_version.match(
                full_version
            ).groups()
        except AttributeError:
            logger.warning(
                "The slack package %s could not be parsed",
                f"{name}-{full_version}",
            )
            return None

        try:
            arch = Architecture(architecture)
        except ValueError:
            arch = Architecture.UNKNOWN

        return SlackPackage(
            name=name,
            arch=arch,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
            build=build,
            target=target or "",
            version=version,
        )
