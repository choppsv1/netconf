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
from lxml import etree
from netconf import NSMAP


class NetconfException (Exception):
    pass


class ChannelClosed (NetconfException):
    pass


class FramingError (NetconfException):
    pass


class SessionError (NetconfException):
    pass


class RPCError (NetconfException):
    def __init__ (self, output, tree, error):
        super(RPCError, self).__init__(output)
        self.tree = tree
        self.error = error

    def _get_error_val (self, value):
        try:
            return self.error.xpath("nc:" + value, namespaces=NSMAP)[0].text
        except IndexError:
            return None

    def get_error_tag (self):
        return self._get_error_val("error-tag")

    def get_error_type (self):
        return self._get_error_val("error-type")

    def get_error_info (self):
        return self._get_error_val("error-info")

    def get_error_severity (self):
        return self._get_error_val("error-severity")

# error-tag
# error-type
RPCERR_TYPE_TRANSPORT = 0
RPCERR_TYPE_RPC = 1
RPCERR_TYPE_PROTOCOL = 2
RPCERR_TYPE_APPLICATIOn = 3
RPCERR_TYPE_ENUM = {
    RPCERR_TYPE_TRANSPORT: "transport",
    RPCERR_TYPE_RPC: "rpc",
    RPCERR_TYPE_PROTOCOL: "protocol",
    RPCERR_TYPE_APPLICATIOn: "application"
}

# error-app-tag
# error-path # xpath associated with error.
# error-message # human readable message describiing error
# error-info


class RPCServerError (NetconfException):
    def __init__ (self, origmsg, etype, tag, **kwargs):
        # Add attrib and nsmap from original message.
        self.reply = etree.Element("rpc-reply", attrib=origmsg.attrib, nsmap=origmsg.nsmap)

        rpcerr = etree.SubElement(self.reply, "rpc-error")

        # We require a type, tag, and severity assuming error for severity.
        if etype in RPCERR_TYPE_ENUM:
            etype = RPCERR_TYPE_ENUM[etype]
        etree.SubElement(rpcerr, "error-type").text = str(etype)

        etree.SubElement(rpcerr, "error-tag").text = tag

        if "severity" not in kwargs:
            etree.SubElement(rpcerr, "error-severity").text = "error"

        # Now convert any other arguments to xml
        for key, value in kwargs.items():
            key = key.replace('_', '-')
            etree.SubElement(rpcerr, "error-{}".format(key)).text = str(value)

        # This sort of sucks for humans
        super(RPCServerError, self).__init__(self.get_reply_msg())

    def get_reply_msg (self):
        return etree.tounicode(self.reply)


class RPCSvrErrBadMsg (RPCServerError):
    def __init__ (self, origmsg):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_RPC, "malformed-message")


class RPCSvrErrNotImpl (RPCServerError):
    def __init__ (self, origmsg):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, "operation-not-supported")

__author__ = 'Christian Hopps'
__date__ = 'February 19 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
