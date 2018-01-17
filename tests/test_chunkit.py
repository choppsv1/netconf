# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# January 12 2018, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2018, Deutsche Telekom AG.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes

from netconf.base import chunkit  # pylint: disable=W0611


def test_chunkit():
    """
    Handle all possible cases until we get firmly in the loop
    including coming out with leftovers

    >>> [x for x in chunkit("", 6, 3, "x")]                 # doctest: +ALLOW_UNICODE
    []
    >>> [x for x in chunkit("0", 6, 3, "x")]                # doctest: +ALLOW_UNICODE
    ['0xx']
    >>> [x for x in chunkit("01", 6, 3, "x")]               # doctest: +ALLOW_UNICODE
    ['01x']
    >>> [x for x in chunkit("012", 6, 3, "x")]              # doctest: +ALLOW_UNICODE
    ['012']
    >>> [x for x in chunkit("0123", 6, 3, "x")]             # doctest: +ALLOW_UNICODE
    ['0123']
    >>> [x for x in chunkit("01234", 6, 3, "x")]            # doctest: +ALLOW_UNICODE
    ['01234']
    >>> [x for x in chunkit("012345", 6, 3, "x")]           # doctest: +ALLOW_UNICODE
    ['012345']
    >>> [x for x in chunkit("0123456", 6, 3, "x")]          # doctest: +ALLOW_UNICODE
    ['0123', '456']
    >>> [x for x in chunkit("01234567", 6, 3, "x")]         # doctest: +ALLOW_UNICODE
    ['01234', '567']
    >>> [x for x in chunkit("012345678", 6, 3, "x")]        # doctest: +ALLOW_UNICODE
    ['012345', '678']
    >>> [x for x in chunkit("0123456789", 6, 3, "x")]       # doctest: +ALLOW_UNICODE
    ['012345', '6789']
    >>> [x for x in chunkit("0123456789a", 6, 3, "x")]      # doctest: +ALLOW_UNICODE
    ['012345', '6789a']
    >>> [x for x in chunkit("0123456789ab", 6, 3, "x")]     # doctest: +ALLOW_UNICODE
    ['012345', '6789ab']
    >>> [x for x in chunkit("0123456789abc", 6, 3, "x")]    # doctest: +ALLOW_UNICODE
    ['012345', '6789', 'abc']
    >>> [x for x in chunkit("0123456789abcd", 6, 3, "x")]   # doctest: +ALLOW_UNICODE
    ['012345', '6789a', 'bcd']
    >>> [x for x in chunkit("0123456789abcde", 6, 3, "x")]  # doctest: +ALLOW_UNICODE
    ['012345', '6789ab', 'cde']
    >>> [x for x in chunkit("0123456789abcdef", 6, 3, "x")]  # doctest: +ALLOW_UNICODE
    ['012345', '6789ab', 'cdef']
    >>> [x for x in chunkit("0123456789abcdefg", 6, 3, "x")]  # doctest: +ALLOW_UNICODE
    ['012345', '6789ab', 'cdefg']
    >>> [x for x in chunkit("0123456789abcdefgh", 6, 3, "x")]  # doctest: +ALLOW_UNICODE
    ['012345', '6789ab', 'cdefgh']
    >>> [x for x in chunkit("0123456789abcdefghi", 6, 3, "x")]  # doctest: +ALLOW_UNICODE
    ['012345', '6789ab', 'cdef', 'ghi']
    >>> [x for x in chunkit("0123456789abcdefghij", 6, 3, "x")]  # doctest: +ALLOW_UNICODE
    ['012345', '6789ab', 'cdefg', 'hij']
    >>> [x for x in chunkit("0123456789abcdefghijk", 6, 3, "x")]  # doctest: +ALLOW_UNICODE
    ['012345', '6789ab', 'cdefgh', 'ijk']
    >>> [x for x in chunkit("", 3)]                         # doctest: +ALLOW_UNICODE
    []
    >>> [x for x in chunkit("0", 3)]                        # doctest: +ALLOW_UNICODE
    ['0']
    >>> [x for x in chunkit("01", 3)]                       # doctest: +ALLOW_UNICODE
    ['01']
    >>> [x for x in chunkit("012", 3)]                      # doctest: +ALLOW_UNICODE
    ['012']
    >>> [x for x in chunkit("0123", 3)]                     # doctest: +ALLOW_UNICODE
    ['012', '3']
    >>> [x for x in chunkit("01234", 3)]                    # doctest: +ALLOW_UNICODE
    ['012', '34']
    >>> [x for x in chunkit("012345", 3)]                   # doctest: +ALLOW_UNICODE
    ['012', '345']
    >>> [x for x in chunkit("0123456", 3)]                  # doctest: +ALLOW_UNICODE
    ['012', '345', '6']
    >>> [x for x in chunkit("01234567", 3)]                 # doctest: +ALLOW_UNICODE
    ['012', '345', '67']
    >>> [x for x in chunkit("012345678", 3)]                # doctest: +ALLOW_UNICODE
    ['012', '345', '678']
    >>> [x for x in chunkit("0123456789", 3)]               # doctest: +ALLOW_UNICODE
    ['012', '345', '678', '9']
    >>> [x for x in chunkit("0123456789a", 3)]              # doctest: +ALLOW_UNICODE
    ['012', '345', '678', '9a']
    >>> [x for x in chunkit("0123456789ab", 3)]             # doctest: +ALLOW_UNICODE
    ['012', '345', '678', '9ab']
    >>> [x for x in chunkit("0123456789abc", 3)]            # doctest: +ALLOW_UNICODE
    ['012', '345', '678', '9ab', 'c']
    """
    """
    Don't handle this right now.
    >>> [x for x in chunkit("", 3, 3, "x")]
    []
    >>> [x for x in chunkit("0", 3, 3, "x")]
    ['0xx']
    >>> [x for x in chunkit("01", 3, 3, "x")]
    ['01x']
    >>> [x for x in chunkit("012", 3, 3, "x")]
    ['012']
    >>> [x for x in chunkit("0123", 3, 3, "x")]
    ['012', '3xx']
    >>> [x for x in chunkit("01234", 3, 3, "x")]
    ['012', '34x']
    >>> [x for x in chunkit("012345", 3, 3, "x")]
    ['012', '345']
    >>> [x for x in chunkit("0123456", 3, 3, "x")]
    ['012', '345', '6xx']
    >>> [x for x in chunkit("01234567", 3, 3, "x")]
    ['012', '345', '67x']
    >>> [x for x in chunkit("012345678", 3, 3, "x")]
    ['012', '345', '678']
    >>> [x for x in chunkit("0123456789", 3, 3, "x")]
    ['012', '345', '678', '9xx']
    >>> [x for x in chunkit("0123456789a", 3, 3, "x")]
    ['012', '345', '678', '9ax']
    >>> [x for x in chunkit("0123456789ab", 3, 3, "x")]
    ['012', '345', '678', '9ab']
    >>> [x for x in chunkit("0123456789abc", 3, 3, "x")]
    ['012', '345', '678', '9ab', 'cxx']
    """


__author__ = 'Christian Hopps'
__date__ = 'January 12 2018'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
