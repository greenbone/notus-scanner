# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from typing import Optional

from .deb import DEBPackage
from .ebuild import EBuildPackage
from .package import Package, PackageType
from .rpm import RPMPackage
from .slackware import SlackPackage
from .windows import WindowsPackage

__SWITCHER = {
    PackageType.RPM: RPMPackage,
    PackageType.DEB: DEBPackage,
    PackageType.EBUILD: EBuildPackage,
    PackageType.SLACK: SlackPackage,
    PackageType.MSP: WindowsPackage,
}


def package_class_by_type(pt: PackageType) -> Optional[Package]:
    """
    package_class_by_type may returns Package if defined otherwise None
    """
    return __SWITCHER.get(pt)
