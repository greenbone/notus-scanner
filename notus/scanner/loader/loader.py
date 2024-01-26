# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import logging
from typing import Optional

from ..models.packages.package import PackageAdvisories

logger = logging.getLogger(__name__)


class AdvisoriesLoader:
    def load_package_advisories(
        self, operating_system: str
    ) -> Optional[PackageAdvisories]:
        raise NotImplementedError()
