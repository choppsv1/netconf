# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# March 23 2019, Christian E. Hopps <chopps@gmail.com>
#
# Copyright (c) 2019 by Christian E. Hopps.
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
#
from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes
import logging
import netconf.client as client
from netconf.error import NetconfError
from mockserver import init_mock_server

logger = logging.getLogger(__name__)
NC_PORT = None
NC_DEBUG = True


def setup_module(unused_module):
    global NC_PORT
    NC_PORT = init_mock_server()


def test_lock_unlock():
    with client.connect_ssh("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG) as session:
        session.lock("running")
        session.unlock("running")
        session.lock("running")
        session.unlock("running")


def test_lock_close_lock():
    with client.connect_ssh("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG) as session:
        session.lock("running")
    with client.connect_ssh("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG) as session:
        session.lock("running")
        session.unlock("running")


def test_lock_unlock_async():
    with client.connect_ssh("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG) as session:
        msg_id = session.lock_async("running")
        _, _, _ = session.wait_reply(msg_id, None)
        msg_id = session.unlock_async("running")
        _, _, _ = session.wait_reply(msg_id, None)


def test_lock_lock():
    with client.connect_ssh("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG) as session:
        session.lock("running")
        try:
            session.lock("running")
        except NetconfError:
            pass
        else:
            assert False
        session.unlock("running")
        session.lock("running")
        session.unlock("running")


def test_unlock_notlocked():
    with client.connect_ssh("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG) as session:
        try:
            session.unlock("running")
        except NetconfError:
            pass
        else:
            assert False


def test_unlock_unlock():
    with client.connect_ssh("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG) as session:
        session.lock("running")
        session.unlock("running")
        try:
            session.unlock("running")
        except NetconfError:
            pass
        else:
            assert False


__author__ = 'Christian E. Hopps'
__date__ = 'March 23 2019'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
