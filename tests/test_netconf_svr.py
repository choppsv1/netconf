# -*- coding: utf-8 eval: (yapf-mode 1) -*-
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
import paramiko as ssh

from sshutil import DisableGlobalCaching
from sshutil.cache import SSHConnectionCache, SSHNoConnectionCache
from netconf import client
from netconf import server
from netconf import util
from netconf.error import RPCError, SessionError

logger = logging.getLogger(__name__)
nc_server = None
NC_PORT = None
SERVER_DEBUG = True
CLIENT_DEBUG = True


class NetconfMethods(server.NetconfMethods):
    def rpc_get(self, session, rpc, filter_or_none):
        del session  # unused
        del filter_or_none  # unused
        return util.elm("nc:ok")

    def rpc_get_config(self, session, rpc, source_elm, filter_or_none):
        del session  # unused
        del source_elm  # unused
        del filter_or_none  # unused
        return util.elm("nc:ok")

    # We have to rethink this as the namespace is not part of the lookup
    def rpc_namespaced(self, unused_session, rpc, *unused_params):
        return util.elm("nc:ok")


def setup_module(unused_module):
    global nc_server

    logging.basicConfig(level=logging.DEBUG)
    DisableGlobalCaching()

    if nc_server is not None:
        logger.error("XXX Called setup_module multiple times")
    else:
        logger.info("Set up netconf server")
        server_ctl = server.SSHUserPassController(username=getpass.getuser(), password="admin")
        nc_server = server.NetconfSSHServer(server_ctl=server_ctl,
                                            server_methods=NetconfMethods(),
                                            port=NC_PORT,
                                            host_key="tests/host_key",
                                            debug=SERVER_DEBUG)


def cleanup_module(unused_module):
    global nc_server
    if nc_server:
        logger.info("Deleting server")

        # Delete the server so that we don't end up with a bunch of logging going on on exit.
        nc_server = None

        # now let's force garbage collection to try and get rid of other objects.
        logger.info("Garbage collecting")
        import gc
        gc.collect()


def test_bad_password():
    try:
        cache = SSHNoConnectionCache("SSH uncached connections")
        session = client.NetconfSSHSession("127.0.0.1",
                                           password="badpass",
                                           port=nc_server.port,
                                           cache=cache)
    except ssh.AuthenticationException:
        pass
    else:
        logger.error("Unexpected success: %s", str(session))
        assert False


def test_not_supported():
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=nc_server.port)
    assert session

    query = "<foobar/>"
    try:
        rval = session.send_rpc(query)
    except RPCError as error:
        assert error.get_error_tag() == "operation-not-supported"
    else:
        logger.error("Unexpected success: %s", str(rval))
        assert False


def test_namespaced_rpc():
    """TEST: Checked that namespaced RPCs work."""
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=nc_server.port)
    assert session

    query = '<namespaced xmlns="some:namespace:1.0"></namespaced>'
    rval = session.send_rpc(query)
    rval = session.send_rpc(query)
    assert rval
    # logger.debug("Get: {}", rval)
    session.close()


def test_malformed():
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=nc_server.port)
    assert session

    query = "<get xmlns='urn:ietf:params:xml:ns:netconf:base:1.0'><foobar/></get><get/>"
    try:
        rval = session.send_rpc(query)
    except RPCError as error:
        assert error.get_error_tag() == "malformed-message"
    else:
        logger.error("Unexpected success: %s", str(rval))
        assert False


def test_malformed_2():
    session = client.NetconfSSHSession("127.0.0.1",
                                       password="admin",
                                       port=nc_server.port,
                                       debug=CLIENT_DEBUG)
    assert session

    query = "</foobar>"
    try:
        rval = session.send_rpc(query)
    except RPCError as error:
        assert error.get_error_tag() == "malformed-message"
        session.close()
    except SessionError as error:
        # If the session closes that's OK too.
        pass
    else:
        logger.error("Unexpected success: %s", str(rval))
        assert False


def test_get():
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=nc_server.port)
    assert session

    query = "<get xmlns='urn:ietf:params:xml:ns:netconf:base:1.0'><filter><status/></filter></get>"
    rval = session.send_rpc(query)
    assert rval
    # logger.debug("Get: {}", rval)
    session.close()


def test_get_config():
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=nc_server.port)
    assert session

    query = "<get-config xmlns='urn:ietf:params:xml:ns:netconf:base:1.0'><source><running/></source></get-config>"
    rval = session.send_rpc(query)
    assert rval
    # logger.debug("Get: {}", rval)
    session.close()


def test_get_config_with_filter():
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=nc_server.port)
    assert session

    query = "<get-config xmlns='urn:ietf:params:xml:ns:netconf:base:1.0'><source><running/></source><filter><foobar/></filter></get-config>"
    rval = session.send_rpc(query)
    assert rval
    session.close()


def test_get_config_missing_source():
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=nc_server.port)
    assert session

    query = "<get-config></get-config>"
    try:
        rval = session.send_rpc(query)
    except RPCError as error:
        assert error.get_error_tag() == "missing-element"
    else:
        logger.error("Unexpected success: %s", str(rval))
        assert False
    session.close()


def test_get_config_with_non_filter():
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=nc_server.port)
    assert session

    query = """<get-config xmlns='urn:ietf:params:xml:ns:netconf:base:1.0'><source><running/></source><foobar/></get-config>"""
    try:
        rval = session.send_rpc(query)
    except RPCError as error:
        assert error.get_error_tag() == "unknown-element"
    else:
        logger.error("Unexpected success: %s", str(rval))
        assert False
    session.close()


def test_close():
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=nc_server.port)
    assert session
    session.close()


def test_multi_session():
    sessions = []
    for unused in range(0, 10):
        sessions.append(client.NetconfSSHSession("127.0.0.1", password="admin",
                                                 port=nc_server.port))


def test_server_close():
    server_ctl = server.SSHUserPassController(username=getpass.getuser(), password="admin")
    for i in range(0, 10):
        logger.debug("Starting %d iteration", i)
        ns = server.NetconfSSHServer(server_ctl=server_ctl,
                                     server_methods=NetconfMethods(),
                                     port=None,
                                     host_key="tests/host_key",
                                     debug=SERVER_DEBUG)
        port = ns.port

        logger.info("Connect to server on port %d", port)
        session = client.NetconfSSHSession("127.0.0.1",
                                           password="admin",
                                           port=port,
                                           debug=CLIENT_DEBUG)
        session.close()
        # NetconfSSHSession.flush()

        logger.debug("Closing")
        ns.close()
        logger.debug("Joining")
        ns.join()
    logger.debug("Test Complete")


def _test_multi_open(client_cache):

    logger.info("Create Server")
    server_ctl = server.SSHUserPassController(username=getpass.getuser(), password="admin")
    ns = server.NetconfSSHServer(server_ctl=server_ctl,
                                 server_methods=NetconfMethods(),
                                 port=NC_PORT,
                                 host_key="tests/host_key",
                                 debug=SERVER_DEBUG)
    port = ns.port

    logger.info("Open sessions")
    sessions = [
        client.NetconfSSHSession("127.0.0.1",
                                 password="admin",
                                 port=port,
                                 debug=CLIENT_DEBUG,
                                 cache=client_cache) for unused in range(0, 25)
    ]

    logger.info("Close sessions")
    for session in sessions:
        session.close()

    logger.info("Reopening")
    sessions = [
        client.NetconfSSHSession("127.0.0.1",
                                 password="admin",
                                 port=port,
                                 debug=CLIENT_DEBUG,
                                 cache=client_cache) for unused in range(0, 25)
    ]

    logger.info("Closeing")
    for session in sessions:
        session.close()

    logger.info("Reopening")
    sessions = [
        client.NetconfSSHSession("127.0.0.1",
                                 password="admin",
                                 port=port,
                                 debug=CLIENT_DEBUG,
                                 cache=client_cache) for unused in range(0, 25)
    ]
    logger.info("Reclosing")
    for session in sessions:
        session.close()

    # Close down the server and join it to make sure it's closed
    logger.info("Closing server")
    ns.close()
    logger.info("Joining server")
    ns.join()

    # Delete the server so that we don't end up with a bunch of logging going on on exit.
    del ns
    del server_ctl


def test_multi_open_no_cache():
    _test_multi_open(SSHNoConnectionCache("SSH uncached connections"))


def test_multi_open_cache():
    _test_multi_open(SSHConnectionCache("test multi open cache", max_channels=50))


__author__ = 'Christian Hopps'
__date__ = 'February 17 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
