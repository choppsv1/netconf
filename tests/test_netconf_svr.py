# -*- coding: utf-8 -*-#
#
# February 17 2015, Christian Hopps <chopps@gmail.com>
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
import getpass
import logging
import sys
import threading
try:
    from lxml import etree
except ImportError:
    from xml.etree import ElementTree as etree

from netconf import client
from netconf import server
from netconf.error import RPCError

logger = logging.getLogger(__name__)
SERVER_DEBUG = True
CLIENT_DEBUG = False
NC_PORT = None
ncserver = None


class NetconfMethods (server.NetconfMethods):
    def rpc_get (self, unused_session, rpc, *unused_params):
        return etree.Element("ok")


def setup_module (unused_module):
    if setup_module.init:
        logger.error("XXX Called setup_module multiple times")
    else:
        global ncserver
        server_ctl = server.SSHUserPassController(username=getpass.getuser(), password="admin")
        ncserver = server.NetconfSSHServer(server_ctl=server_ctl,
                                           server_methods=NetconfMethods(),
                                           port=NC_PORT,
                                           host_key="tests/host_key",
                                           debug=SERVER_DEBUG)
        setup_module.init = True
setup_module.init = False


def cleanup_module (unused_module):
    if setup_module.init:
        logger.error("Done with server")


def test_not_supported ():
    session = client.NetconfSSHSession("127.0.0.1", port=ncserver.port)
    assert session

    query = "<get-config><barfoo/></get-config>"
    try:
        rval = session.send_rpc(query)
    except RPCError as error:
        assert error.get_error_tag() == "operation-not-supported"
    else:
        logger.error("Unexpected success: {}", rval)
        assert False


def test_malformed ():
    session = client.NetconfSSHSession("127.0.0.1", port=ncserver.port)
    assert session

    query = "<get><foobar/></get><get/>"
    try:
        rval = session.send_rpc(query)
    except RPCError as error:
        assert error.get_error_tag() == "malformed-message"
    else:
        logger.error("Unexpected success: {}", rval)
        assert False


def test_get ():
    session = client.NetconfSSHSession("127.0.0.1", port=ncserver.port)
    assert session

    query = "<get><status/></get>"
    rval = session.send_rpc(query)
    assert rval
    # logger.debug("Get: {}", rval)


def test_close ():
    session = client.NetconfSSHSession("127.0.0.1", port=ncserver.port)
    assert session
    session.close()


def test_multi_session ():
    sessions = []
    for unused in range(0, 10):
        sessions.append(client.NetconfSSHSession("127.0.0.1", port=ncserver.port))


def test_multi_open ():
    logger.info("Create Server")
    server_ctl = server.SSHUserPassController(username=getpass.getuser(), password="admin")
    ns = server.NetconfSSHServer(server_ctl=server_ctl,
                                 server_methods=NetconfMethods(),
                                 port=NC_PORT,
                                 host_key="tests/host_key",
                                 debug=SERVER_DEBUG)
    port = ns.port

    logger.info("Open sessions")
    sessions = [ client.NetconfSSHSession("127.0.0.1", port=port, debug=CLIENT_DEBUG) for unused in range(0, 25) ]

    logger.info("Close sessions")
    for session in sessions:
        session.close()

    logger.info("Reopening")
    sessions = [ client.NetconfSSHSession("127.0.0.1", port=port, debug=CLIENT_DEBUG) for unused in range(0, 25) ]

    logger.info("Closeing")
    for session in sessions:
        session.close()

    logger.info("Reopening")
    sessions = [ client.NetconfSSHSession("127.0.0.1", port=port, debug=CLIENT_DEBUG) for unused in range(0, 25) ]
    logger.info("Reclosing")
    for session in sessions:
        session.close()

__author__ = 'Christian Hopps'
__date__ = 'February 17 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
