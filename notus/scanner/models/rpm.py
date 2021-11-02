# slightly adjusted from https://github.com/ihiji/version_utils
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""
rpm module for version_utils

Contains RPM parsing and comparison operations for version_utils.
Public methods include:

    * :any:`compare_packages`: compare two RPM package strings, e.g.
      ``gcc-4.4.7-16.el6.x86_64`` and ``gcc-4.4.7-17.el6.x86_64``
    * :any:`compare_versions`: compare two RPM version strings (the
      bit between the dashes in an RPM package string)
    * :any:`package`: parse an RPM package string to get name, epoch,
      version, release, and architecture information. Returns as a
      :any:`common.Package` object.
"""

import logging
import re

from ..errors import RpmError

_rpm_re = re.compile(r"(\S+)-(?:(\d*):)?(.*)-(~?\w+[\w.]*)")

logger = logging.getLogger(__name__)


# Return values:
#   a_newer: a is newer than b, return 1
#   _B_NEWER: b is newer than a, return -1
#   _A_EQ_B: a and b are equal, return 0
_A_NEWER = 1
_B_NEWER = -1
_A_EQ_B = 0


def compare_packages(rpm_str_a, rpm_str_b, arch_provided=True):
    """Compare two RPM strings to determine which is newer

    Parses version information out of RPM package strings of the form
    returned by the ``rpm -q`` command and compares their versions to
    determine which is newer. Provided strings *do not* require an
    architecture at the end, although if providing strings without
    architecture, the ``arch_provided`` parameter should be set to
    False.

    Note that the packages do not have to be the same package (i.e.
    they do not require the same name or architecture).

    :param str rpm_str_a: an rpm package string
    :param str rpm_str_b: an rpm package string
    :param bool arch_provided: whether package strings contain
        architecture information
    :return: 1 (``a`` is newer), 0 (versions are equivalent), or -1
        (``b`` is newer)
    :rtype: int
    """
    logger.debug("resolve_versions(%s, %s)", rpm_str_a, rpm_str_b)
    evr_a = parse_package(rpm_str_a, arch_provided)["EVR"]
    evr_b = parse_package(rpm_str_b, arch_provided)["EVR"]
    return label_compare(evr_a, evr_b)


def compare_evrs(evr_a, evr_b):
    """Compare two EVR tuples to determine which is newer

    This method compares the epoch, version, and release of the
    provided package strings, assuming that epoch is 0 if not provided.
    Comparison is performed on the epoch, then the version, and then
    the release. If at any point a non-equality is found, the result is
    returned without any remaining comparisons being performed (e.g. if
    the epochs of the packages differ, the versions are releases are
    not compared).

    :param tuple evr_a: an EVR tuple
    :param tuple evr_b: an EVR tuple
    """
    a_epoch, a_ver, a_rel = evr_a
    b_epoch, b_ver, b_rel = evr_b
    if a_epoch != b_epoch:
        return _A_NEWER if a_epoch > b_epoch else _B_NEWER
    ver_comp = compare_versions(a_ver, b_ver)
    if ver_comp != _A_EQ_B:
        return ver_comp
    rel_comp = compare_versions(a_rel, b_rel)
    return rel_comp


def label_compare(evr_a, evr_b):
    """Convenience function to provide the same behavior as
    labelCompare from rpm-python.

    To be used as a drop-in replacement for labelCompare, thus the
    utilization of the non-standard camelCase variable name.

    To use the version_utils version and fall back to rpm:

    try:
        from version_utils.rpm import labelCompare
    except ImportError:
        from rpm import labelCompare

    :param tuple evr_a: an EVR tuple
    :param tuple evr_b: an EVR tuple
    """
    return compare_evrs(evr_a, evr_b)


def compare_versions(version_a, version_b):
    """Compare two RPM version strings

    Compares two RPM version strings and returns an integer indicating
    the result of the comparison. The method of comparison mirrors that
    used by RPM, so results should be the same for any standard RPM
    package.

    To perform the comparison, the strings are first checked for
    equality. If they are equal, the versions are equal. Otherwise,
    each string is converted to a character list, and a comparison
    loop is started using these lists.

    In the comparison loop, first any non-alphanumeric, non-~
    characters are trimmed from the front of the list. Then if the first
    character from both ``a`` and ``b`` is a ~ (tilde), it is trimmed.
    The ~ (tilde) character indicates that a given package or version
    should be considered older (even if it is numerically larger), so
    if ``a`` begins with a tilde, ``b`` is newer, and vice-versa. At
    this point, if the length of either list has been reduced to 0, the
    loop is exited. If characters remain in the list, the
    :any:`_get_block_result` function is used to pop consecutive digits
    or letters from the front of hte list and compare them. The result
    of the block comparison is returned if the blocks are not equal.
    The loop then begins again.

    If the loop exits without returning a value, the lengths of the
    remaining character lists are compared. If they have the same length
    (usually 0, since all characters have been popped), they are
    considered to be equal. Otherwise, whichever is longer is considered
    to be newer. Generally, unequal length will be due to one character
    list having been completely consumed while some characters remain on
    the other, for example when comparing 1.05b to 1.05.

    :param unicode version_a: An RPM version or release string
    :param unicode version_b: An RPM version or release string
    :return: 1 (if ``a`` is newer), 0 (if versions are equal), or -1
        (if ``b`` is newer)
    :rtype: int
    :raises RpmError: if an a type is passed that cannot be converted to
        a list
    """
    logger.debug("compare_versions(%s, %s)", version_a, version_b)
    if version_a == version_b:
        return _A_EQ_B
    try:
        chars_a, chars_b = list(version_a), list(version_b)
    except TypeError:
        raise RpmError(
            f"Could not compare {version_a} to {version_b}"
        ) from None

    while len(chars_a) != 0 and len(chars_b) != 0:
        logger.debug("starting loop comparing %s " "to %s", chars_a, chars_b)
        _check_leading(chars_a, chars_b)
        if chars_a[0] == "~" and chars_b[0] == "~":
            map(lambda x: x.pop(0), (chars_a, chars_b))
        elif chars_a[0] == "~":
            return _B_NEWER
        elif chars_b[0] == "~":
            return _A_NEWER
        if len(chars_a) == 0 or len(chars_b) == 0:
            break
        block_res = _get_block_result(chars_a, chars_b)
        if block_res != _A_EQ_B:
            return block_res
    if len(chars_a) == len(chars_b):
        logger.debug("versions are equal")
        return _A_EQ_B
    else:
        logger.debug("versions not equal")
        return _A_NEWER if len(chars_a) > len(chars_b) else _B_NEWER


def parse_package(package_string, arch_included=True):
    """Parse an RPM version string to get name, version, and arch

    Splits most (all tested) RPM version strings into name, epoch,
    version, release, and architecture. Epoch (also called serial) is
    an optional component of RPM versioning and is also optional in
    version strings provided to this function. RPM assumes the epoch
    to be 0 if it is not provided, so that behavior is mirrored here.

    **Deprecated** since version 0.2.0. Use :any:`rpm.package` instead.

    :param str package_string: an RPM version string of the form
        returned by the ``rpm -q`` command
    :param bool arch_included: default True - version strings may
        optionally be provided without the trailing architecture. If
        providing such strings, set this option to False
    :return: a dictionary with all parsed package information
    :rtype: dict
    """
    # Yum sets epoch values to 0 if they are not specified
    logger.debug("parse_package(%s, %s)", package_string, arch_included)
    default_epoch = "0"
    arch = None
    if arch_included:
        char_list = list(package_string)
        arch = _pop_arch(char_list)
        package_string = "".join(char_list)
        logger.debug("updated version_string: %s", package_string)
    try:
        name, epoch, version, release = _rpm_re.match(package_string).groups()
    except AttributeError:
        raise RpmError(
            f"Could not parse package string: {package_string}"
        ) from None

    if epoch == "" or epoch is None:
        epoch = default_epoch

    info = {"name": name, "EVR": (epoch, version, release), "arch": arch}
    logger.debug("parsed information: %s", info)
    return info


def _pop_arch(char_list):
    """Pop the architecture from a version string and return it

    Returns any portion of a string following the final period. In rpm
    version strings, this corresponds to the package architecture.

    :param list char_list: an rpm version string in character list form
    :return: the parsed architecture as a string
    :rtype: str
    """
    logger.debug("_pop_arch(%s)", char_list)
    arch_list = []
    char = char_list.pop()
    while char != ".":
        arch_list.insert(0, char)
        try:
            char = char_list.pop()
        except IndexError:  # Raised for a string with no periods
            raise RpmError(
                "Could not parse an architecture. Did you mean to "
                "set the arch_included flag to False?"
            ) from None
    logger.debug("arch chars: %s", arch_list)
    return "".join(arch_list)


def _check_leading(*char_lists):
    """Remove any non-alphanumeric or non-~ leading characters

    Checks the beginning of any provided lists for non-alphanumeric or
    non-~ (tilde) leading characters and removes them if found.
    Operates on (and possibly alters) the passed list.

    :param list char_list: a list or lists of characters
    :return: None
    :rtype: None
    """
    logger.debug("_check_leading(%s)", char_lists)
    for char_list in char_lists:
        while (
            len(char_list) != 0
            and not char_list[0].isalnum()
            and not char_list[0] == "~"
        ):
            char_list.pop(0)
        logger.debug("updated list: %s", char_list)


def _trim_zeros(*char_lists):
    """Trim any zeros from provided character lists

    Checks the beginning of any provided lists for '0's and removes any
    such leading zeros. Operates on (and possibly) alters the passed
    list

    :param list char_lists: a list or lists of characters
    :return: None
    :rtype: None
    """
    logger.debug("_trim_zeros(%s)", char_lists)
    for char_list in char_lists:
        while len(char_list) != 0 and char_list[0] == "0":
            char_list.pop(0)
        logger.debug("updated block: %s", char_list)


def _pop_digits(char_list):
    """Pop consecutive digits from the front of list and return them

    Pops any and all consecutive digits from the start of the provided
    character list and returns them as a list of string digits.
    Operates on (and possibly alters) the passed list.

    :param list char_list: a list of characters
    :return: a list of string digits
    :rtype: list
    """
    logger.debug("_pop_digits(%s)", char_list)
    digits = []
    while len(char_list) != 0 and char_list[0].isdigit():
        digits.append(char_list.pop(0))
    logger.debug("got digits: %s", digits)
    logger.debug("updated char list: %s", char_list)
    return digits


def _pop_letters(char_list):
    """Pop consecutive letters from the front of a list and return them

    Pops any and all consecutive letters from the start of the provided
    character list and returns them as a list of characters. Operates
    on (and possibly alters) the passed list

    :param list char_list: a list of characters
    :return: a list of characters
    :rtype: list
    """
    logger.debug("_pop_letters(%s)", char_list)
    letters = []
    while len(char_list) != 0 and char_list[0].isalpha():
        letters.append(char_list.pop(0))
    logger.debug("got letters: %s", letters)
    logger.debug("updated char list: %s", char_list)
    return letters


def _compare_blocks(block_a, block_b):
    """Compare two blocks of characters

    Compares two blocks of characters of the form returned by either
    the :any:`_pop_digits` or :any:`_pop_letters` function. Blocks
    should be character lists containing only digits or only letters.
    Both blocks should contain the same character type (digits or
    letters).

    The method of comparison mirrors the method used by RPM. If the
    blocks are digit blocks, any leading zeros are trimmed, and
    whichever block is longer is assumed to be larger. If the resultant
    blocks are the same length, or if the blocks are non-numeric, they
    are checked for string equality and considered equal if the string
    equality comparison returns True. If not, whichever evaluates as
    greater than the other (again in string comparison) is assumed to be
    larger.

    :param list block_a: an all numeric or all alphabetic character
        list
    :param list block_b: an all numeric or all alphabetic character
        list. Alphabetic or numeric character should match ``block_a``
    :return: 1 (if ``a`` is newer), 0 (if versions are equal) or
        -1 (if ``b`` is newer)
    :rtype: int
    """
    logger.debug("_compare_blocks(%s, %s)", block_a, block_b)
    if block_a[0].isdigit():
        _trim_zeros(block_a, block_b)
        if len(block_a) != len(block_b):
            logger.debug("block lengths are not equal")
            return _A_NEWER if len(block_a) > len(block_b) else _B_NEWER
    if block_a == block_b:
        logger.debug("blocks are equal")
        return _A_EQ_B
    else:
        logger.debug("blocks are not equal")
        return _A_NEWER if block_a > block_b else _B_NEWER


def _get_block_result(chars_a, chars_b):
    """Get the first block from two character lists and compare

    If character list ``a`` begins with a digit, the :any:`_pop_digit`
    function is called on both lists to get blocks of all consecutive
    digits at the start of each list. If the length of the block
    returned when popping digits for ``b`` is zero (``b`` started with a
    letter), ``a`` is newer. If ``b`` is of nonzero length, the blocks
    are compared using :any:`_compare_blocks`.

    If character list ``a`` begins with a letter, the
    :any:`_pop_letter` function is called on both lists to get blocks
    of all consecutive letters at the start of each list. If the length
    of the block returned when popping letters for ``b`` is zero (``b``
    started with a digit), ``b`` is newer. If ``b`` is of nonzero
    length, blocks ``a`` and ``b`` are compared using
    :any:`_compare_blocks`.

    :param list chars_a: a list of characters derived from a version
        string
    :param list chars_b: a list of characters derived from a version
        string
    :return: 1 (if ``a`` is newer), 0 (if versions are equal), or
        -1 (if ``b`` is newer)
    :rtype: int
    """
    logger.debug("_get_block_result(%s, %s)", chars_a, chars_b)
    first_is_digit = chars_a[0].isdigit()
    pop_func = _pop_digits if first_is_digit else _pop_letters
    return_if_no_b = _A_NEWER if first_is_digit else _B_NEWER
    block_a, block_b = pop_func(chars_a), pop_func(chars_b)
    if len(block_b) == 0:
        logger.debug("blocks are equal")
        return return_if_no_b
    return _compare_blocks(block_a, block_b)
