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


class NotusScannerError(Exception):
    """Base Class for error raised in Notus Scanner"""


class AdvisoriesLoadingError(NotusScannerError):
    """A problem while loading an Advisory has occurred"""


class Sha256SumLoadingError(NotusScannerError):
    """A problem while loading sha256sums has occurred"""


class PackageError(NotusScannerError):
    """Base Class for errors raised in package handling"""


class MessageParsingError(NotusScannerError):
    """A problem while parsing an incoming message"""


class ConfigFileError(NotusScannerError):
    """ "A problem while parsing the config file has occurred"""
