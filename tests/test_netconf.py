# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# December 23 2014, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2015, Deutsche Telekom AG
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
import netconf.client as client
from netconf.error import NetconfError
from mockserver import init_mock_server

logger = logging.getLogger(__name__)
NC_PORT = None
NC_DEBUG = True


def setup_module(unused_module):
    global NC_PORT
    NC_PORT = init_mock_server()


def test_query():
    query = """
    <get>
    <filter type="subtree">
    <devices xmlns="http://tail-f.com/ns/ncs">
    <global-settings/>
    </devices>
    </filter>
    </get>
    """

    query = """
    <get>
    <filter type="xpath" select="/devices/global-settings"/>
    </get>
    """
    logger.info("Connecting to 127.0.0.1 port %d", NC_PORT)
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG)
    session.send_rpc(query)


def test_bad_query():
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG)
    try:
        unused, unused, output = session.send_rpc("<get><unknown/></get>")
        logger.warning("Got unexpected output: %s", str(output))
    except NetconfError:
        pass


def test_context_manager():
    select = """
    <devices xmlns="http://tail-f.com/ns/ncs">
    <global-settings/>
    </devices>
    """
    select = "/devices/global-settings"
    logger.info("Connecting to 127.0.0.1 port %d", NC_PORT)
    with client.connect_ssh("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG) as session:
        session.get(select)


__author__ = 'Christian Hopps'
__date__ = 'December 23 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
