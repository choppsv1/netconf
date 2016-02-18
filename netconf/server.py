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
import sys
import traceback
import logging
import io
import os
import select
import socket
if sys.platform == 'win32' and sys.version_info < (3, 5):
    import backports.socketpair
import threading
import paramiko as ssh
from lxml import etree
from netconf import base
import netconf.error as ncerror
from netconf import NSMAP
from netconf import qmap
from netconf import util

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

                bits = exp = None
                try:
                    bits = int(values[0])
                except ValueError:
                    # Type 1 or type 2, type 1 is bits in second value
                    options_ktype = values[0]
                    try:
                        bits = int(values[1])
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
                        key = ssh.RSAKey(data=base64.decodestring(data.encode('ascii')))
                    elif ktype == "ssh-dss":
                        key = ssh.DSSKey(data=base64.decodestring(data.encode('ascii')))
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

    def __init__ (self, pktstream, methods, session_id, debug):
        super(NetconfServerSession, self).__init__(pktstream, debug, session_id)
        self.methods = methods

        super(NetconfServerSession, self)._open_session(True)

    def __del__ (self):
        self.close()
        super(NetconfServerSession, self).__del__()

    def __str__ (self):
        return "NetconfServerSession(sid:{})".format(self.session_id)

    def close (self):
        # XXX should be invoking a method in self.methods
        if self.debug:
            logger.debug("%s: Closing.", str(self))

        super(NetconfServerSession, self).close()

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
            logger.debug("%s: Not Impl msg-id: %s, rpc: %s", str(self), msg_id, rpc.iterchildren().next().tag)
        raise ncerror.RPCSvrErrNotImpl(rpc)

    def _handle_message (self, msg):
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
                    # logger.debug("%s: Calling method: %s", str(self), str(methodname))
                    reply = method(self, rpc, *params)
                    self.send_rpc_reply(reply, rpc)
                except NotImplementedError:
                    raise ncerror.RPCSvrErrNotImpl(rpc)
            except ncerror.RPCSvrErrBadMsg as msgerr:
                if self.new_framing:
                    self.send_message(msgerr.get_reply_msg())
                else:
                    # If we are 1.0 we have to simply close the connection
                    # as we are not allowed to send this error
                    logger.warning("Closing 1.0 session due to malformed message")
                    raise ncerror.SessionError(msg, "Malformed message")
            except ncerror.RPCServerError as error:
                self.send_message(error.get_reply_msg())
            except Exception as exception:
                error = ncerror.RPCSvrException(rpc, exception)
                self.send_message(error.get_reply_msg())


class NetconfSSHServerSocket (object):
    """An SSH socket connection from a client"""
    def __init__ (self, server_ctl, server_methods, server, newsocket, addr, debug):
        self.server_methods = server_methods
        self.server = server
        self.client_socket = newsocket
        self.client_addr = addr
        self.debug = debug
        self.server_ctl = server_ctl

        try:
            if self.debug:
                logger.debug("%s: Opening SSH connection", str(self))

            self.ssh = ssh.Transport(self.client_socket)
            self.ssh.add_server_key(self.server.host_key)
            self.ssh.start_server(server=self.server_ctl)
        except ssh.AuthenticationException as error:
            self.client_socket.close()
            self.client_socket = None
            logger.error("Authentication failed:  %s", str(error))
            raise

        self.thread = threading.Thread(None,
                                       self._accept_chan_thread,
                                       name="NetconfSSHAcceptThread")
        self.thread.daemon = True
        self.thread.start()

    def __str__ (self):
        return "NetconfSSHServerSocket(client: {})".format(self.client_addr)

    def _shutdown (self):
        # XXX we need some sort of locking here...
        if self.ssh:
            self.ssh.close()
            self.ssh = None

        if self.client_socket:
            self.client_socket.close()
            self.client_socket = None

    def _accept_chan_thread (self):
        try:
            while True:
                if self.debug:
                    logger.debug("%s: Accepting channel connections", str(self))

                channel = self.ssh.accept(timeout=None)
                if channel is None:
                    if not self.ssh.is_active():
                        logger.debug("%s: Got channel as None: exiting", str(self))
                        return

                    logger.warn("%s: Got channel as None on active.", str(self))
                    continue

                # XXX for some reason we are accepting another connection after we close the previous channel.
                sid = self.server.allocate_session_id()
                if self.debug:
                    logger.debug("%s: Creating session-id %s", str(self), str(sid))
                session = NetconfServerSession(channel, self.server_methods, sid, self.debug)
                if self.debug:
                    logger.debug("%s: Client session-id %s created: %s", str(self), str(sid), str(session))
        except Exception as error:
            if self.debug:
                logger.error("%s: Unexpected exception: %s: %s", str(self), str(error), traceback.format_exc())
            else:
                logger.error("%s: Unexpected exception: %s closing", str(self), str(error))
            self.client_socket.close()
            self.client_socket = None
            self.server.remove_socket(self)


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


class NetconfSSHServer (object):
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
        if server_ctl is None:
            server_ctl = SSHUserPassController()
        self.server_ctl = server_ctl
        self.server_methods = server_methods if server_methods is not None else NetconfMethods()
        self.debug = debug
        if port is None:
            port = 0
        self.port = port
        self.host_key = None

        # Load the host key for our netconf server.
        if host_key:
            assert os.path.exists(host_key)
            self.host_key = ssh.RSAKey.from_private_key_file(host_key)
        else:
            for keypath in [ "/etc/ssh/ssh_host_rsa_key",
                             "/etc/ssh/ssh_host_dsa_key"]:
                # XXX check we have access
                if os.path.exists(keypath):
                    self.host_key = ssh.RSAKey.from_private_key_file(keypath)
                    break

        # Bind first to IPv6, if the OS supports binding per AF then the IPv4
        # will succeed, otherwise the IPv6 will support both AF.
        for pname, host, proto in [ ("IPv6", '::', socket.AF_INET6), ("IPv4", '', socket.AF_INET) ]:
            protosocket = socket.socket(proto, socket.SOCK_STREAM)
            protosocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if self.debug:
                logger.debug("Server binding to proto %s port %s", str(pname), str(port))
            if proto == socket.AF_INET:
                try:
                    protosocket.bind((host, port))
                    # XXX need the actual bind busy error
                except Exception:
                    break
            else:
                protosocket.bind((host, port, 0, 0))

            if port == 0:
                assigned = protosocket.getsockname()
                self.port = assigned[1]

            if self.debug:
                logger.debug("Server listening on proto %s port %s", str(pname), str(port))
            protosocket.listen(100)

            # Create a socket to cause closure.
            self.close_wsocket, self.close_rsocket = socket.socketpair()

            self.lock = threading.Lock()
            self.session_id = 0
            self.sockets = []

            self.thread = threading.Thread(None,
                                           self._accept_socket_thread,
                                           name="NetconfAcceptThread " + pname,
                                           args=[protosocket])
            self.thread.daemon = True
            self.thread.start()

    def close (self):
        with self.lock:
            self.close_wsocket.send(b"!")

    def join (self):
        "Wait on server to terminate"
        self.thread.join()

    def allocate_session_id (self):
        with self.lock:
            sid = self.session_id
            self.session_id += 1
            return sid

    def remove_socket (self, serversocket):
        with self.lock:
            self.sockets.remove(serversocket)

    def _accept_socket_thread (self, proto_sock):
        """Call from within a thread to accept connections."""

        # XXX should probably select here so we can cause closure
        while True:
            if self.debug:
                logger.debug("%s: Accepting connections", str(self))

            rfds, unused, unused = select.select([proto_sock, self.close_rsocket], [], [])
            if self.close_rsocket in rfds:
                if self.debug:
                    logger.debug("%s: Got close notification closing down server", str(self))

                # with self.lock:
                #     sockets = list(self.sockets)
                sockets = list(self.sockets)
                for sock in sockets:
                    if sock in self.sockets:
                        sock._shutdown()

                # Not until we have a real shutdown
                # assert not self.sockets
                return

            if proto_sock in rfds:
                client, addr = proto_sock.accept()
                if self.debug:
                    logger.debug("%s: Client accepted: %s: %s", str(self), str(client), str(addr))
                try:
                    with self.lock:
                        sock = NetconfSSHServerSocket(self.server_ctl,
                                                      self.server_methods,
                                                      self,
                                                      client,
                                                      addr,
                                                      self.debug)
                        self.sockets.append(sock)
                except ssh.AuthenticationException:
                    pass

    def __str__ (self):
        return "NetconfSSHServer(port={})".format(self.port)


__author__ = 'Christian Hopps'
__date__ = 'February 19 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
