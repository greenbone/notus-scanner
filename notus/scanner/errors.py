# SPDX-FileCopyrightText: 2021-2024 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later


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
