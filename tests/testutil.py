# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# February 11 2020, Christian E. Hopps <chopps@gmail.com>
#
# Copyright (c) 2020 by Christian E. Hopps.
# All rights reserved.
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
import logging

logger = logging.getLogger(__name__)


def xml_eq(a, b):
    if len(a) != len(b):
        logger.error("len(a) (%d) != len(b) (%d)", len(a), len(b))
        return False

    if a.tag != b.tag:
        logger.error("a.tag (%s) != b.tag (%s)", str(a.tag), str(b.tag))
        return False

    if a is not None and len(a):
        for ae, be in zip(a, b):
            if not xml_eq(ae, be):
                return False

    if a.text is None and b.text is not None:
        logger.error("a.text (None) != b.text (%s)", str(b.text))
        return False
    elif a.text is not None and b.text is None:
        logger.error("a.text (%s) != b.text (None)", str(a.text))
        return False
    elif a.text:
        atext = a.text.strip()
        btext = b.text.strip()
        if atext == btext:
            return True
        logger.error("a.text (%s) != b.text (%s)", atext, btext)
        return False
    return True
