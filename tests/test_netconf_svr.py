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


class NetconfMethods (server.NetconfMethods):
    def rpc_get (self, unused_session, rpc, *unused_params):
        return etree.Element("ok")


def setup_module (unused_module):
    if setup_module.init:
        logger.error("XXX Called setup_module multiple times")
    else:
        server.NetconfSSHServer(server_ctl=server.SSHUserPassController(username=getpass.getuser(),
                                                                        password="admin"),
                                server_methods=NetconfMethods(),
                                port=9930,
                                host_key="tests/host_key",
                                debug=SERVER_DEBUG)
        # setup_module.init = True
setup_module.init = False


def cleanup_module (unused_module):
    if setup_module.init:
        logger.error("XXX Done with server")
        import time
        time.sleep(10)


def test_not_supported ():
    session = client.NetconfSSHSession("127.0.0.1", port=9930)
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
    session = client.NetconfSSHSession("127.0.0.1", port=9930)
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
    session = client.NetconfSSHSession("127.0.0.1", port=9930)
    assert session

    query = "<get><status/></get>"
    rval = session.send_rpc(query)
    assert rval
    # logger.debug("Get: {}", rval)


def test_close ():
    session = client.NetconfSSHSession("127.0.0.1", port=9930)
    assert session
    session.close()


def test_multi_session ():
    sessions = []
    for unused in range(0, 10):
        sessions.append(client.NetconfSSHSession("127.0.0.1", port=9930))


def _init_logging (prefix, level, svr):
    logbook.compat.redirect_logging()

    logbook.default_handler.level = level

    def inject_threadid (record):
        if 'threadName' not in record.extra:
            thread = threading.current_thread()
            thread_name = thread.name
            record.extra['threadName'] = thread_name
        return record
    if svr:
        handler = logbook.StreamHandler(sys.stderr, logbook.ERROR, bubble=False)
    else:
        handler = logbook.StreamHandler(sys.stdout, logbook.ERROR, bubble=False)
    #handler.format_string = "{record.channel}: {record.threadName}: {record.message}"
    handler.format_string = ("{record.time:%y-%m-%d %H:%M:%S.%f}: " +
                             prefix +
                             ": {record.level_name}: {record.extra[threadName]}: {record.message}")
    handler.level = level
    handler.push_application()
    logbook.Processor(inject_threadid).push_application()


def test_multi_open ():
    # XXX want this is a different process?
    # _init_logging("MULTI", logbook.WARNING, True)

    logger.info("Create Server")
    ns = server.NetconfSSHServer(server_ctl=server.SSHUserPassController(username=getpass.getuser(),
                                                                         password="admin"),
                                 server_methods=NetconfMethods(),
                                 port=9931,
                                 host_key="tests/host_key",
                                 debug=SERVER_DEBUG)
    del ns

    import gc
    gc.collect()

    logger.info("Open sessions")
    sessions = [ client.NetconfSSHSession("127.0.0.1", port=9931, debug=CLIENT_DEBUG) for unused in range(0, 25) ]

    logger.info("Close sessions")
    for session in sessions:
        session.close()

    logger.info("Reopening")
    sessions = [ client.NetconfSSHSession("127.0.0.1", port=9931, debug=CLIENT_DEBUG) for unused in range(0, 25) ]

    logger.info("Closeing")
    for session in sessions:
        session.close()

    logger.info("Reopening")
    sessions = [ client.NetconfSSHSession("127.0.0.1", port=9931, debug=CLIENT_DEBUG) for unused in range(0, 25) ]
    logger.info("Reclosing")
    for session in sessions:
        session.close()

__author__ = 'Christian Hopps'
__date__ = 'February 17 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
