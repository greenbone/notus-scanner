# slightly adjusted from https://github.com/ihiji/version_utils
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
deb module for version_utils

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
from typing import Tuple
from dataclasses import dataclass
from packaging.version import parse

from .package import Package, PackageComparision

_deb_compile = re.compile(r"(.*)-(?:(\d*):)?(.*)-(.*)")
_deb_compile_wo_revision = re.compile(r"(.*)-(?:(\d*):)?(.*)")
_deb_compile_version = re.compile(r"(?:(\d*):)?(\d.*)-(.*)")
_deb_compile_version_wo_revision = re.compile(r"(?:(\d*):)?(\d.*)")


logger = logging.getLogger(__name__)

# Epoch, Version, Revision Tuple
EVRTuple = Tuple[str, str, str]


@dataclass
class DEBPackage(Package):
    """Represents a .deb based package"""

    upstream_version: str
    debian_revision: str
    epoch: str

    __hash__ = Package.__hash__

    def _compare(self, other: Package) -> PackageComparision:
        a_version = parse(self.full_version)
        b_version = parse(other.full_version)

        if a_version == b_version:
            return PackageComparision.EQUAL

        return (
            PackageComparision.A_NEWER
            if a_version > b_version
            else PackageComparision.B_NEWER
        )

    @staticmethod
    def from_full_name(full_name: str):
        if not full_name:
            return None

        full_name = full_name.strip()
        # Try to get data with
        try:
            name, epoch, upstream_version, debian_revision = _deb_compile.match(
                full_name
            ).groups()
        except AttributeError:
            try:
                name, epoch, upstream_version = _deb_compile_wo_revision.match(
                    full_name
                ).groups()
                debian_revision = ""
            except AttributeError:
                logger.warning(
                    "The deb package %s could not be parsed", full_name
                )
                return None

        if not epoch:
            epoch = "0"
            full_version = f"{upstream_version}"
        else:
            full_version = f"{epoch}:{upstream_version}"

        if debian_revision:
            full_version = f"{full_version}-{debian_revision}"

        return DEBPackage(
            name=name,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
            epoch=epoch,
            upstream_version=upstream_version,
            debian_revision=debian_revision,
        )

    @staticmethod
    def from_name_and_full_version(name: str, full_version: str):
        if not name or not full_version:
            return None
        name = name.strip()
        full_version = full_version.strip()
        try:
            (
                epoch,
                upstream_version,
                debian_revision,
            ) = _deb_compile_version.match(full_version).groups()
        except AttributeError:
            try:
                (
                    epoch,
                    upstream_version,
                ) = _deb_compile_version_wo_revision.match(
                    full_version
                ).groups()
                debian_revision = ""
            except AttributeError:
                logger.warning(
                    "The deb package %s %s could not be parsed",
                    name,
                    full_version,
                )
                return None

        if not epoch:
            epoch = "0"

        return DEBPackage(
            name=name,
            full_name=f"{name}-{full_version}",
            full_version=full_version,
            epoch=epoch,
            upstream_version=upstream_version,
            debian_revision=debian_revision,
        )
