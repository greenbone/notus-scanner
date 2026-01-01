# SPDX-FileCopyrightText: 2021-2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from .json import JSONAdvisoriesLoader
from .loader import AdvisoriesLoader

__all__ = ("JSONAdvisoriesLoader", "AdvisoriesLoader")
