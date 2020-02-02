# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# February 19 2015, Christian Hopps <chopps@gmail.com>
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
from contextlib import contextmanager
import logging
import io
import threading
import socket

from lxml import etree
from monotonic import monotonic
import sshutil.conn
from netconf import NSMAP, qmap
from netconf.base import NetconfSession
from netconf.error import RPCError, SessionError, ReplyTimeoutError
from netconf import util

logger = logging.getLogger(__name__)


def _is_filter(select):
    return select.lstrip().startswith("<")


def _get_selection(elm, select):
    if select is None or len(select) == 0:
        return

    # Add non-default namespaces to filter element
    nsmap = {key: value for key, value in NSMAP.items() if key and key != "nc"}
    felm = util.subelm(elm, "nc:filter", nsmap=nsmap)

    if hasattr(select, "nsmap"):
        felm.attrib[qmap("nc") + "type"] = "subtree"
        felm.append(select)
    elif _is_filter(select):
        felm.attrib[qmap("nc") + "type"] = "subtree"
        felm.append(etree.fromstring(select))
    else:
        felm.attrib[qmap("nc") + "type"] = "xpath"
        felm.attrib[qmap("nc") + "select"] = select


class Timeout(object):
    def __init__(self, timeout):
        self.start_time = monotonic()
        if timeout is None:
            self.end_time = None
        else:
            self.end_time = self.start_time + timeout

    def is_expired(self):
        if self.end_time is None:
            return False
        return self.end_time < monotonic()

    def remaining(self):
        if self.end_time is None:
            return None
        ctime = monotonic()
        if self.end_time < ctime:
            return 0
        else:
            return self.end_time - ctime


class NetconfClientSession(NetconfSession):
    """Netconf Protocol"""
    def __init__(self, stream, debug=False):
        super(NetconfClientSession, self).__init__(stream, debug, None)
        self.message_id = 0
        self.closing = False
        self.rpc_out = {}

        # Condition to handle rpc_out queue
        self.cv = threading.Condition()

        super(NetconfClientSession, self)._open_session(False)

    def __str__(self):
        return "NetconfClientSession(sid:{})".format(self.session_id)

    def close(self):
        """Close the session."""

        if self.debug:
            logger.debug("%s: Closing session.", str(self))

        reply = None
        try:
            # So we need a lock here to check these members.
            send = False
            with self.cv:
                if self.session_id is not None and self.is_active():
                    send = True

            if send:
                self.send_rpc_async("<close-session/>", noreply=True)
                # Don't wait for a reply the session is closed!
        except socket.error:
            if self.debug:
                logger.debug("Got socket error sending close-session request, ignoring")

        super(NetconfClientSession, self).close()

        if self.debug:
            logger.debug("%s: Closed: %s", str(self), str(reply))

    def is_reply_ready(self, msg_id):
        """Check whether reply is ready (or session closed)"""
        with self.cv:
            if not self.is_active():
                raise SessionError("Session closed while checking for reply")
            return self.rpc_out[msg_id] is not None

    def wait_reply(self, msg_id, timeout=None):
        """Wait for a reply to a given RPC message ID.

        :param msg_id: the RPC message ID returned from one of the async method calls
        :return: (Message as an lxml tree, Parsed reply content, Parsed message content).
        :rtype: (lxml.etree, lxml.Element, lxml.Element)
        :raises: RPCError, SessionError
        """
        assert msg_id in self.rpc_out

        check_timeout = Timeout(timeout)

        self.cv.acquire()
        # XXX need to make sure the channel doesn't close
        while self.rpc_out[msg_id] is None and self.is_active():
            remaining = check_timeout.remaining()

            self.cv.wait(remaining)
            if self.rpc_out[msg_id] is not None:
                break

            if check_timeout.is_expired():
                raise ReplyTimeoutError(
                    "Timeout ({}s) while waiting for RPC reply to msg-id: {}".format(
                        timeout, msg_id))

        if not self.is_active():
            self.cv.release()
            raise SessionError("Session closed while waiting for reply")

        tree, reply, msg = self.rpc_out[msg_id]
        del self.rpc_out[msg_id]
        self.cv.release()

        error = reply.xpath("nc:rpc-error", namespaces=NSMAP)
        if error:
            raise RPCError(msg, tree, error[0])

        # data = reply.xpath("nc:data", namespaces=self.nsmap)
        # ok = reply.xpath("nc:ok", namespaces=self.nsmap)
        return tree, reply, msg

    def send_rpc_async(self, rpc, noreply=False):
        """Send a generic RPC to the server and await the reply.

        :param rpc: The XML of the netconf RPC, not including the <nc:rpc> tag.
        :type rpc: str or `lxml.Element`
        :param noreply: True if no reply is required.
        :type noreply: Boolean

        :return: The RPC message id which can be passed to wait_reply for the results.
        """

        # We use strings to allow users to pass malformed data.
        if hasattr(rpc, "nsmap"):
            rpc = etree.tounicode(rpc)

        # Get the next message id
        with self.cv:
            assert self.session_id is not None
            msg_id = self.message_id
            self.message_id += 1

        if self.debug:
            logger.debug("%s: Sending RPC message-id: %s", str(self), str(msg_id))

        def sendit():
            self.send_message(
                """<nc:rpc nc:message-id="{}" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">{}</nc:rpc>"""
                .format(msg_id, rpc))

        if noreply:
            sendit()
            return None

        with self.cv:
            sendit()
            # Mark us as expecting a reply
            self.rpc_out[msg_id] = None

        return msg_id

    def send_rpc(self, rpc, timeout=None):
        """Send a generic RPC to the server and await the reply.

        :param rpc (string): The XML of the netconf RPC, not including the <rpc> tag.
        :return: (Message as an lxml tree, Parsed reply content, Parsed message content).
        :rtype: (lxml.etree, lxml.Element, lxml.Element)
        :raises: RPCError, SessionError
        """
        msg_id = self.send_rpc_async(rpc)
        return self.wait_reply(msg_id, timeout)

    def edit_config_async(self, target, method, newconf):
        """Operate on config in ~target~ using ~newconf~ according to ~method~ ("merge", "replace",
        "none"). If "none" then no nodes are modified until a element specifies the mode as an
        attribute.

        :param target: the target of the config.
        :param method: "merge", "replace", "none".
        :param newconf: The new configuration.
        :return: The RPC message id which can be passed to wait_reply for the results.
        :raises: SessionError
        """
        if hasattr(target, "nsmap"):
            target = target.tag
        elif ":" not in target:
            target = "nc:" + target

        rpc = """
<nc:edit-config>
  <nc:target>
    <""" + target + """/>
  </nc:target>
"""
        if method is not None and method != "":
            rpc += "  <nc:default-operation>{}</nc:default-operation>\n".format(method)
        rpc += newconf
        rpc += "</nc:edit-config>\n"
        return self.send_rpc_async(rpc)

    def edit_config(self, target="running", method="", newconf="", timeout=None):
        """Operate on config in ~target~ using ~newconf~ according to ~method~ ("merge", "replace" or
        "none"). If "none" then no nodes are modified until a element specifies the mode as an
        attribute.

        :param target: the target of the config, defaults to "running".
        :param method: "merge" (netconf default), "replace" or "none".
        :param newconf: The new configuration.
        :param timeout: A value in fractional seconds to wait for the operation to complete or
                        `None` for no timeout.
        :return: The result of the edit operation
        :rtype: lxml.Element
        :raises: ReplyTimeoutError, RPCError, SessionError
        """
        msg_id = self.edit_config_async(target, method, newconf)
        _, reply, _ = self.wait_reply(msg_id, timeout)
        return reply

    def get_config_async(self, source, select):
        """Get config asynchronously for a given source from the server. If `select` is
        specified it is either an XPATH expression or XML subtree filter for
        selecting a subsection of the config.

        :param source: the source of the config, defaults to "running".
        :param select: An XML subtree filter or XPATH expression to select a subsection of config.
        :return: The RPC message id which can be passed to wait_reply for the results.
        :raises: SessionError
        """
        getelm = util.elm("nc:get-config")
        if not hasattr(source, "nsmap"):
            source = util.elm(source if ":" in source or source.startswith("{") else "nc:" + source)
        util.subelm(util.subelm(getelm, "nc:source"), source)
        _get_selection(getelm, select)
        return self.send_rpc_async(getelm)

    def get_config(self, source="running", select=None, timeout=None):
        """Get config for a given source from the server. If `select` is specified it
        is either an XPATH expression or XML subtree filter for selecting a
        subsection of the config. If `timeout` is not `None` it specifies how
        long to wait for the get operation to complete.

        :param source: the source of the config, defaults to "running".
        :param select: An XML subtree filter or XPATH expression to select a subsection of config.
        :param timeout: A value in fractional seconds to wait for the operation to complete or
                        `None` for no timeout.
        :return: The Parsed XML config (i.e., "<nc:config>...</config>".)
        :rtype: lxml.Element
        :raises: ReplyTimeoutError, RPCError, SessionError
        """
        msg_id = self.get_config_async(source, select)
        _, reply, _ = self.wait_reply(msg_id, timeout)
        return reply.find("nc:data", namespaces=NSMAP)

    def get_async(self, select):
        """Get operational state asynchronously from the server. If `select` is
        specified it is either an XPATH expression or XML subtree filter for
        selecting a subsection of the state. If `timeout` is not `None` it
        specifies how long to wait for the get operation to complete.

        :param select: A XML subtree filter or XPATH expression to select a subsection of state.
        :return: The RPC message id which can be passed to wait_reply for the results.
        :raises: SessionError
        """

        getelm = util.elm("nc:get")
        _get_selection(getelm, select)
        return self.send_rpc_async(getelm)

    def get(self, select=None, timeout=None):
        """Get operational state from the server. If `select` is specified it is either
        an XPATH expression or XML subtree filter for selecting a subsection of
        the state. If `timeout` is not `None` it specifies how long to wait for
        the get operation to complete.

        :param select: A XML subtree filter or XPATH expression to select a subsection of state.
        :param timeout: A value in fractional seconds to wait for the operation to complete or
                       `None` for no timeout.
        :return: The Parsed XML state (i.e., "<data>...</data>".)
        :rtype: lxml.Element
        :raises: ReplyTimeoutError, RPCError, SessionError
        """
        msg_id = self.get_async(select)
        _, reply, _ = self.wait_reply(msg_id, timeout)
        return reply.find("nc:data", namespaces=NSMAP)

    def lock_async(self, target):
        """Lock target datastore asynchronously.

        :param target: A string specifying the config datastore to lock.
        :return: The RPC message id which can be passed to wait_reply for the results.
        :raises: SessionError
        """
        lockelm = util.elm("nc:lock")
        if not hasattr(target, "nsmap"):
            target = util.elm(target if ":" in target or target.startswith("{") else "nc:" + target)
        util.subelm(util.subelm(lockelm, "nc:target"), target)
        return self.send_rpc_async(lockelm)

    def lock(self, target="running", timeout=None):
        """Lock target datastore asynchronously.

        If `timeout` is not `None` it specifies how long to wait for the get operation to complete.

        :param target: A string specifying the config datastore to lock.
        :return: None
        :raises: RPCError, SessionError
        """
        msg_id = self.lock_async(target)
        _, reply, _ = self.wait_reply(msg_id, timeout)
        return reply.find("nc:data", namespaces=NSMAP)

    def unlock_async(self, target):
        """Unlock target datastore asynchronously.

        :param target: A string specifying the config datastore to unlock.
        :return: The RPC message id which can be passed to wait_reply for the results.
        :raises: SessionError
        """
        unlockelm = util.elm("nc:unlock")
        if not hasattr(target, "nsmap"):
            target = util.elm(target if ":" in target or target.startswith("{") else "nc:" + target)
        util.subelm(util.subelm(unlockelm, "nc:target"), target)
        return self.send_rpc_async(unlockelm)

    def unlock(self, target="running", timeout=None):
        """Unlock target datastore asynchronously.

        If `timeout` is not `None` it specifies how long to wait for the get operation to complete.

        :param target: A string specifying the config datastore to unlock.
        :return: None
        :raises: RPCError, SessionError
        """
        msg_id = self.unlock_async(target)
        _, reply, _ = self.wait_reply(msg_id, timeout)
        return reply.find("nc:data", namespaces=NSMAP)

    # ----------------
    # Internal Methods
    # ----------------

    def _reader_exits(self):
        """This function is called from the session reader thread as it exits. No more
        messages will be read from the session socket.
        """
        if self.debug:
            logger.debug("%s: Reader thread exited notifying all.", str(self))
        with self.cv:
            self.cv.notify_all()

    def _reader_handle_message(self, msg):
        """This function is called from the session reader thread to process a received
        framed netconf message.
        """
        try:
            tree = etree.parse(io.BytesIO(msg.encode('utf-8')))
            if not tree:
                raise SessionError(msg, "Invalid XML from server.")
        except etree.XMLSyntaxError:
            raise SessionError(msg, "Invalid XML from server.")

        replies = tree.xpath("/nc:rpc-reply", namespaces=NSMAP)
        if not replies:
            raise SessionError(msg, "No rpc-reply found")

        for reply in replies:
            try:
                msg_id = int(reply.get(qmap("nc") + 'message-id'))
            except (TypeError, ValueError):
                # # Cisco is returning errors without message-id attribute which
                # # is non-rfc-conforming it is doing this for any malformed XML
                # # not simply missing message-id attribute.
                # error = reply.xpath("nc:rpc-error", namespaces=self.nsmap)
                # if error:
                #     raise RPCError(received, tree, error[0])
                raise SessionError(msg, "No valid message-id attribute found")

            # Queue the message
            with self.cv:
                try:
                    if msg_id not in self.rpc_out:
                        if self.debug:
                            logger.debug("Ignoring unwanted reply for message-id %s", str(msg_id))
                        return
                    elif self.rpc_out[msg_id] is not None:
                        logger.warning(
                            "Received multiple replies for message-id %s:"
                            " before: %s now: %s", str(msg_id), str(self.rpc_out[msg_id]), str(msg))

                    if self.debug:
                        logger.debug("%s: Received rpc-reply message-id: %s", str(self),
                                     str(msg_id))
                    self.rpc_out[msg_id] = tree, reply, msg
                except Exception as error:
                    logger.debug("%s: Unexpected exception: %s", str(self), str(error))
                    raise
                finally:
                    self.cv.notify_all()


class NetconfSSHSession(NetconfClientSession):
    def __init__(self,
                 host,
                 port=830,
                 username=None,
                 password=None,
                 debug=False,
                 cache=None,
                 proxycmd=None):
        """A netconf SSH client session.

        If `username` is not specified then it will be obtained with
        getpass.getuser(). If an ssh agent is available it will be used for
        authentication. A users .ssh/config will be processed for making the ssh
        connection and any proxycmd found therein will also be utilized.

        :param host: The host to connect to.
        :param port: The port to connect to.
        :param username: The username to connect with. If not specified getpass.getuser()
                         will be used.
        :param password: The password or passkey to authenticate with.
        :param debug: Enable debug logging
        :param cache: An SSH cache (`sshutil.cache`) to use for caching connections.
        :param proxycmd: A proxy command string for connecting with
        """
        if username is None:
            import getpass
            username = getpass.getuser()
        stream = sshutil.conn.SSHClientSession(host,
                                               port,
                                               "netconf",
                                               username,
                                               password,
                                               debug,
                                               cache=cache,
                                               proxycmd=proxycmd)
        super(NetconfSSHSession, self).__init__(stream, debug)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


@contextmanager
def connect_ssh(host,
                port=830,
                username=None,
                password=None,
                debug=False,
                cache=None,
                proxycmd=None):
    """A context manager method for opening a netconf SSH session.

    If `username` is not specified then it will be obtained with
    getpass.getuser(). If an ssh agent is available it will be used for
    authentication. A users .ssh/config will be processed for making the ssh
    connection and any proxycmd found therein will also be utilized.

    :param host: The host to connect to.
    :param port: The port to connect to.
    :param username: The username to connect with. If not specified getpass.getuser() will be used
    :param password: The password or passkey to authenticate with.
    :param debug: Enable debug logging
    :param cache: An SSH cache (`sshutil.cache`) to use for caching connections.
    :param proxycmd: A proxy command string for connecting with
    """
    session = NetconfSSHSession(host, port, username, password, debug, cache, proxycmd)
    yield session
    session.close()


__author__ = 'Christian Hopps'
__date__ = 'February 19 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
