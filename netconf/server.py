# -*- coding: utf-8 -*-#
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
import io
import logging
import os
import sys
import threading
import paramiko as ssh
from lxml import etree
import sshutil.server

from netconf import base
import netconf.error as ncerror
from netconf import NSMAP
from netconf import qmap
from netconf import util

if sys.platform == 'win32' and sys.version_info < (3, 5):
    import backports.socketpair             # pylint: disable=E0401,W0611

logger = logging.getLogger(__name__)

try:
    import pam
    have_pam = True
except ImportError:
    have_pam = False


class SSHAuthController (ssh.ServerInterface):
    def __init__ (self, users=None):
        self.event = threading.Event()
        self.users = users
        self.users_keys = {}
        if have_pam:
            self.pam = pam.pam()
        else:
            self.pam = None

    def get_user_auth_keys (self, username):
        """Parse the users's authorized_keys file if any to look for authorized keys"""
        if username in self.users_keys:
            return self.users_keys[username]

        self.users_keys[username] = []

        userdir = os.path.expanduser("~" + username)
        if not userdir:
            return self.users_keys[username]

        keyfile = os.path.join(userdir, ".ssh/authorized_keys")
        if not keyfile or not os.path.exists(keyfile):
            return self.users_keys[username]

        with open(keyfile) as f:
            for line in f.readlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                values = [ x.strip() for x in line.split() ]

                exp = None
                try:
                    int(values[0])      # bits value?
                except ValueError:
                    # Type 1 or type 2, type 1 is bits in second value
                    options_ktype = values[0]
                    try:
                        int(values[1])  # bits value?
                    except ValueError:
                        # type 2 with options
                        ktype = options_ktype
                        data = values[1]
                    else:
                        # Type 1 no options.
                        exp = int(values[1])
                        data = values[2]
                else:
                    # Type 1 no options.
                    exp = int(values[1])
                    data = values[2]

                # XXX For now skip type 1 keys
                if exp is not None:
                    continue

                if data:
                    import base64
                    if ktype == "ssh-rsa":
                        key = ssh.RSAKey(data=base64.decodebytes(data.encode('ascii')))
                    elif ktype == "ssh-dss":
                        key = ssh.DSSKey(data=base64.decodebytes(data.encode('ascii')))
                    else:
                        key = None
                    if key:
                        self.users_keys[username].append(key)
        return self.users_keys[username]

    def get_allowed_auths (self, username):
        # This is only called after the user fails some other authentication type.
        if self.users is None:
            users = [ username ]
        else:
            users = self.users
        allowed = []
        if username in users:
            if self.pam:
                allowed.append("password")

            if self.get_user_auth_keys(username):
                allowed.append("publickey")
        logger.debug("Allowed methods for user %s: %s", str(username), str(allowed))
        return allowed

    def check_auth_none (self, unused_username):
        return ssh.AUTH_FAILED

    def check_auth_publickey (self, username, offered_key):
        if not self.get_user_auth_keys(username):
            return ssh.AUTH_FAILED
        for ukey in self.users_keys[username]:
            if ukey == offered_key:
                return ssh.AUTH_SUCCESSFUL
        return ssh.AUTH_FAILED

    def check_auth_password (self, username, password):
        # Don't allow empty user or empty passwords
        if not username or not password:
            return ssh.AUTH_FAILED
        if self.pam and self.pam.authenticate(username, password):
            return ssh.AUTH_SUCCESSFUL
        return ssh.AUTH_FAILED

    def check_channel_request (self, kind, channel):
        if kind == "session":
            return ssh.OPEN_SUCCEEDED
        return ssh.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request (self, channel, name):
        self.event.set()
        return name == "netconf"


class SSHUserPassController (ssh.ServerInterface):
    def __init__ (self, username=None, password=None):
        self.username = username
        self.password = password
        self.event = threading.Event()

    def get_allowed_auths (self, unused_username):
        return ["password"]

    def check_auth_none (self, unused_username):
        return ssh.AUTH_FAILED

    def check_auth_password (self, username, password):
        if self.username == username and self.password == password:
            return ssh.AUTH_SUCCESSFUL
        return ssh.AUTH_FAILED

    def check_channel_request (self, kind, channel):
        if kind == "session":
            return ssh.OPEN_SUCCEEDED
        return ssh.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request (self, channel, name):
        self.event.set()
        return name == "netconf"


class NetconfServerSession (base.NetconfSession):
    """Netconf Server-side Session Protocol"""
    handled_rpc_methods = set(["close-session",
                               "kill-session"])

    def __init__ (self, channel, server, unused_extra_args, debug):
        self.server = server

        sid = server.allocate_session_id()
        if debug:
            logger.debug("NetconfServerSession: Creating session-id %s", str(sid))

        self.methods = server.server_methods
        super(NetconfServerSession, self).__init__(channel, debug, sid)
        super(NetconfServerSession, self)._open_session(True)

        if self.debug:
            logger.debug("%s: Client session-id %s created", str(self), str(sid))

    def __del__ (self):
        self.close()
        super(NetconfServerSession, self).__del__()

    def __str__ (self):
        return "NetconfServerSession(sid:{})".format(self.session_id)

    def close (self):
        # XXX should be invoking a method in self.methods?
        if self.debug:
            logger.debug("%s: Closing.", str(self))

        try:
            super(NetconfServerSession, self).close()
        except EOFError:
            if self.debug:
                logger.debug("%s: EOF error while closing", str(self))

        if self.debug:
            logger.debug("%s: Closed.", str(self))

    def send_rpc_reply (self, rpc_reply, origmsg):
        reply = etree.Element(qmap('nc') + "rpc-reply", attrib=origmsg.attrib, nsmap=origmsg.nsmap)
        try:
            rpc_reply.getchildren                           # pylint: disable=W0104
            reply.append(rpc_reply)
        except AttributeError:
            reply.extend(rpc_reply)
        ucode = etree.tounicode(reply, pretty_print=True)
        if self.debug:
            logger.debug("%s: Sending RPC-Reply: %s", str(self), str(ucode))
        self.send_message(ucode)

    def send_rpc_reply_error (self, error):
        self.send_message(error.get_reply_msg())

    def _rpc_not_implemented (self, unused_session, rpc, *unused_params):
        if self.debug:
            msg_id = rpc.get('message-id')
            logger.debug("%s: Not Impl msg-id: %s", str(self), msg_id)
        raise ncerror.RPCSvrErrNotImpl(rpc)

    def reader_exits (self):
        if self.debug:
            logger.debug("%s: Reader thread exited.", str(self))
        return

    def reader_handle_message (self, msg):
        """Handle a message, lock is already held"""
        if not self.session_open:
            return

        # Any error with XML encoding here is going to cause a session close
        # Technically we should be able to return malformed message I think.
        try:
            tree = etree.parse(io.BytesIO(msg.encode('utf-8')))
            if not tree:
                raise ncerror.SessionError(msg, "Invalid XML from client.")
        except etree.XMLSyntaxError:
            logger.warning("Closing session due to malformed message")
            raise ncerror.SessionError(msg, "Invalid XML from client.")

        rpcs = tree.xpath("/nc:rpc", namespaces=NSMAP)
        if not rpcs:
            raise ncerror.SessionError(msg, "No rpc found")

        for rpc in rpcs:
            try:
                msg_id = rpc.get('message-id')
                if self.debug:
                    logger.debug("%s: Received rpc message-id: %s", str(self), msg_id)
            except (TypeError, ValueError):
                raise ncerror.SessionError(msg, "No valid message-id attribute found")

            try:
                # Get the first child of rpc as the method name
                rpc_method = rpc.getchildren()
                if len(rpc_method) != 1:
                    if self.debug:
                        logger.debug("%s: Bad Msg: msg-id: %s", str(self), msg_id)
                    raise ncerror.RPCSvrErrBadMsg(rpc)
                rpc_method = rpc_method[0]

                rpcname = rpc_method.tag.replace(qmap('nc'), "")
                params = rpc_method.getchildren()
                paramslen = len(params)

                if self.debug:
                    logger.debug("%s: RPC: %s: paramslen: %s",
                                 str(self),
                                 rpcname,
                                 str(paramslen))

                if rpcname == "close-session":
                    # XXX should be RPC-unlocking if need be
                    if self.debug:
                        logger.debug("%s: Received close-session msg-id: %s", str(self), msg_id)
                    self.send_rpc_reply(etree.Element("ok"), rpc)
                    self.close()
                    # XXX should we also call the user method if it exists?
                    return
                elif rpcname == "kill-session":
                    # XXX we are supposed to cleanly abort anything underway
                    if self.debug:
                        logger.debug("%s: Received kill-session msg-id: %s", str(self), msg_id)
                    self.send_rpc_reply(etree.Element("ok"), rpc)
                    self.close()
                    # XXX should we also call the user method if it exists?
                    return
                elif rpcname == "get":
                    # Validate GET parameters

                    if paramslen > 1:
                        # XXX need to specify all elements not known
                        raise ncerror.RPCSvrErrBadMsg(rpc)
                    if params and not util.filter_tag_match(params[0], "nc:filter"):
                        raise ncerror.RPCSvrUnknownElement(rpc, params[0])
                    if not params:
                        params = [ None ]
                elif rpcname == "get-config":
                    # Validate GET-CONFIG parameters

                    # XXX verify that the source parameter is present
                    if paramslen > 2:
                        # XXX need to specify all elements not known
                        raise ncerror.RPCSvrErrBadMsg(rpc)
                    source_param = rpc_method.find("nc:source", namespaces=NSMAP)
                    if source_param is None:
                        raise ncerror.RPCSvrMissingElement(rpc, util.elm("nc:source"))
                    filter_param = None
                    if paramslen == 2:
                        filter_param = rpc_method.find("nc:filter", namespaces=NSMAP)
                        if filter_param is None:
                            unknown_elm = params[0] if params[0] != source_param else params[1]
                            raise ncerror.RPCSvrUnknownElement(rpc, unknown_elm)
                    params = [ source_param, filter_param ]

                #------------------
                # Call the method.
                #------------------

                try:
                    # Handle any namespaces or prefixes in the tag, other than
                    # "nc" which was removed above. Of course, this does not handle
                    # namespace collisions, but that seems reasonable for now.
                    rpcname = rpcname.rpartition("}")[-1]
                    method_name = "rpc_" + rpcname.replace('-', '_')
                    method = getattr(self.methods, method_name, self._rpc_not_implemented)
                    if self.debug:
                        logger.debug("%s: Calling method: %s", str(self), method_name)
                    reply = method(self, rpc, *params)
                    self.send_rpc_reply(reply, rpc)
                except NotImplementedError:
                    raise ncerror.RPCSvrErrNotImpl(rpc)
            except ncerror.RPCSvrErrBadMsg as msgerr:
                if self.new_framing:
                    if self.debug:
                        logger.debug("%s: RPCSvrErrBadMsg: %s", str(self), str(msgerr))
                    self.send_message(msgerr.get_reply_msg())
                else:
                    # If we are 1.0 we have to simply close the connection
                    # as we are not allowed to send this error
                    logger.warning("Closing 1.0 session due to malformed message")
                    raise ncerror.SessionError(msg, "Malformed message")
            except ncerror.RPCServerError as error:
                if self.debug:
                    logger.debug("%s: RPCServerError: %s", str(self), str(error))
                self.send_message(error.get_reply_msg())
            except EOFError:
                if self.debug:
                    logger.debug("%s: Got EOF in reader_handle_message", str(self))
                error = ncerror.RPCSvrException(rpc, EOFError("EOF"))
                self.send_message(error.get_reply_msg())
            except EOFError:
                if self.debug:
                    logger.debug("Got EOF in reader_handle_message")
            except Exception as exception:
                if self.debug:
                    logger.debug("%s: Got unexpected exception in reader_handle_message: %s",
                                 str(self),
                                 str(exception))
                error = ncerror.RPCSvrException(rpc, exception)
                self.send_message(error.get_reply_msg())


class NetconfMethods (object):
    """This is an abstract class that is used to document the server methods functionality

    The server return not-implemented if the method is not found in the methods object,
    so feel free to use duck-typing here (i.e., no need to inherit)
    """

    def nc_append_capabilities (self, capabilities):        # pylint: disable=W0613
        """The server should append any capabilities it supports to capabilities"""
        return

    def rpc_get (self, session, rpc, filter_or_none):       # pylint: disable=W0613
        """Passed the filter element or None if not present"""
        raise ncerror.RPCSvrErrNotImpl(rpc)

    def rpc_get_config (self, session, rpc, source_elm, filter_or_none):  # pylint: disable=W0613
        """Passed the source element"""
        raise ncerror.RPCSvrErrNotImpl(rpc)

    #---------------------------------------------------------------------------
    # These definitions will change to include required parameters like get and
    # get-config
    #---------------------------------------------------------------------------

    # XXX The API WILL CHANGE consider unfinished
    def rpc_copy_config (self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # XXX The API WILL CHANGE consider unfinished
    def rpc_delete_config (self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # XXX The API WILL CHANGE consider unfinished
    def rpc_edit_config (self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # XXX The API WILL CHANGE consider unfinished
    def rpc_lock (self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # XXX The API WILL CHANGE consider unfinished
    def rpc_unlock (self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)


class NetconfSSHServer (sshutil.server.SSHServer):
    """A netconf server"""
    def __del__ (self):
        logger.error("Deleting %s", str(self))

    def __init__ (self,
                  server_ctl=None,
                  server_methods=None,
                  port=830,
                  host_key=None,
                  debug=False):
        """
        server_methods is a an object that implements the Netconf RPC methods
        for the server. The method names are "rpc_X" where X is the netconf method
        with dash (-) replaced by underscore (_) e.g., rpc_get_config.
        """
        self.server_methods = server_methods if server_methods is not None else NetconfMethods()
        self.session_id = 1
        super(NetconfSSHServer, self).__init__(server_ctl,
                                               server_session_class=NetconfServerSession,
                                               port=port,
                                               host_key=host_key,
                                               debug=debug)

    def allocate_session_id (self):
        with self.lock:
            sid = self.session_id
            self.session_id += 1
            return sid

    def __str__ (self):
        return "NetconfSSHServer(port={})".format(self.port)


__author__ = 'Christian Hopps'
__date__ = 'February 19 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
