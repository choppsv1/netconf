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
from lxml import etree
from netconf import NSMAP


class NetconfException(Exception):
    pass


class ChannelClosed(NetconfException):
    pass


class FramingError(NetconfException):
    pass


class SessionError(NetconfException):
    pass


class ReplyTimeoutError(NetconfException):
    pass


class RPCError(NetconfException):
    def __init__(self, output, tree, error):
        super(RPCError, self).__init__(output)
        self.tree = tree
        self.error = error

    def _get_error_val(self, value):
        try:
            return self.error.xpath("nc:" + value, namespaces=NSMAP)[0].text
        except IndexError:
            return None

    def get_error_tag(self):
        return self._get_error_val("error-tag")

    def get_error_type(self):
        return self._get_error_val("error-type")

    def get_error_info(self):
        return self._get_error_val("error-info")

    def get_error_severity(self):
        return self._get_error_val("error-severity")


# RFC6241

# error-type
RPCERR_TYPE_TRANSPORT = 0
RPCERR_TYPE_RPC = 1
RPCERR_TYPE_PROTOCOL = 2
RPCERR_TYPE_APPLICATION = 3
RPCERR_TYPE_ENUM = {
    RPCERR_TYPE_TRANSPORT: "transport",
    RPCERR_TYPE_RPC: "rpc",
    RPCERR_TYPE_PROTOCOL: "protocol",
    RPCERR_TYPE_APPLICATION: "application"
}

# error-tag
RPCERR_TAG_IN_USE = "in-use"
RPCERR_TAG_INVALID_VALUE = "invalid-value"
RPCERR_TAG_TOO_BIG = "too-big"
RPCERR_TAG_MISSING_ATTRIBUTE = "missing-attribute"
RPCERR_TAG_BAD_ATTRIBUTE = "bad-attribute"
RPCERR_TAG_UNKNOWN_ATTRIBUTE = "unknown-attribute"
RPCERR_TAG_MISSING_ELEMENT = "missing-element"
RPCERR_TAG_BAD_ELEMENT = "bad-element"
RPCERR_TAG_UNKNOWN_ELEMENT = "unknown-element"
RPCERR_TAG_UNKNOWN_NAMESPACE = "unknown-namespace"
RPCERR_TAG_ACCESS_DENIED = "access-denied"
RPCERR_TAG_LOCK_DENIED = "lock-denied"
RPCERR_TAG_RESOURCE_DENIED = "resource-denied"
RPCERR_TAG_ROLLBACK_FAILED = "rollback-failed"
RPCERR_TAG_DATA_EXISTS = "data-exists"
RPCERR_TAG_DATA_MISSING = "data-missing"
RPCERR_TAG_OPERATION_NOT_SUPPORTED = "operation-not-supported"
RPCERR_TAG_OPERATION_FAILED = "operation-failed"
RPCERR_TAG_MALFORMED_MESSAGE = "malformed-message"
RPCERR_TAG_PARTIAL_OPERATION = "partial-operation"

# error-app-tag
# error-path # xpath associated with error.
# error-message # human readable message describiing error
# error-info


class RPCServerError(NetconfException):
    def __init__(self, origmsg, etype, tag, **kwargs):
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
            # Allow info to be a dictionary we convert to sub-elements
            if key == "info" and hasattr(value, "items"):
                infoelm = etree.SubElement(rpcerr, "error-info")
                for ikey, ivalue in value.items():
                    ikey = ikey.replace('_', '-')
                    etree.SubElement(infoelm, "{}".format(ikey)).text = str(ivalue)
            else:
                key = key.replace('_', '-')
                etree.SubElement(rpcerr, "error-{}".format(key)).text = str(value)

        # This sort of sucks for humans
        super(RPCServerError, self).__init__(self.get_reply_msg())

    def get_reply_msg(self):
        return etree.tounicode(self.reply)


class RPCSvrException(RPCServerError):
    def __init__(self, origmsg, exception, **kwargs):
        RPCServerError.__init__(
            self,
            origmsg,
            RPCERR_TYPE_PROTOCOL,
            RPCERR_TAG_OPERATION_FAILED,
            info=str(exception),
            **kwargs)


# Need to deprecate this as we are overriding a built-in
TimeoutError = ReplyTimeoutError  # pylint: disable=W0622

# -------------------------------------------------------------
# Netconf Mandated Errors - Ordered alphabetically by base type
# -------------------------------------------------------------


class _RPCSvrAccessDenied(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_ACCESS_DENIED, **kwargs)


class RPCSvrApplicationAccessDenied(_RPCSvrAccessDenied):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrAccessDenied.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProtocolAccessDenied(_RPCSvrAccessDenied):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrAccessDenied.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class _RPCSvrBadAttribute(RPCServerError):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        RPCServerError.__init__(
            self,
            origmsg,
            etype,
            RPCERR_TAG_BAD_ATTRIBUTE,
            info={'bad-element': element.tag,
                  'bad-attibute': attribute},
            **kwargs)


class RPCSvrApplicationBadAttribute(_RPCSvrBadAttribute):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _RPCSvrBadAttribute.__init__(self, origmsg, element, attribute, RPCERR_TYPE_APPLICATION,
                                     **kwargs)


class RPCSvrProtocolBadAttribute(_RPCSvrBadAttribute):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _RPCSvrBadAttribute.__init__(self, origmsg, element, attribute, RPCERR_TYPE_PROTOCOL,
                                     **kwargs)


class RPCSvrRPCBadAttribute(_RPCSvrBadAttribute):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _RPCSvrBadAttribute.__init__(self, origmsg, element, attribute, RPCERR_TYPE_RPC, **kwargs)


class _RPCSvrBadElement(RPCServerError):
    def __init__(self, origmsg, element, etype, **kwargs):
        RPCServerError.__init__(
            self,
            origmsg,
            etype,
            RPCERR_TAG_BAD_ELEMENT,
            info={'bad-element': element.tag},
            **kwargs)


class RPCSvrApplicationBadElement(_RPCSvrBadElement):
    def __init__(self, origmsg, element, **kwargs):
        _RPCSvrBadElement.__init__(self, origmsg, element, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProcotolBadElement(_RPCSvrBadElement):
    def __init__(self, origmsg, element, **kwargs):
        _RPCSvrBadElement.__init__(self, origmsg, element, RPCERR_TYPE_PROTOCOL, **kwargs)


class RPCSvrDataExists(RPCServerError):
    def __init__(self, origmsg, **kwargs):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, RPCERR_TAG_DATA_EXISTS,
                                **kwargs)


class RPCSvrDataMissing(RPCServerError):
    def __init__(self, origmsg, **kwargs):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, RPCERR_TAG_DATA_MISSING,
                                **kwargs)


class _RPCSvrInvalidValue(RPCServerError):
    def __init__(self, origmsg, erype, **kwargs):
        RPCServerError.__init__(self, origmsg, erype, RPCERR_TAG_INVALID_VALUE, **kwargs)


class RPCSvrApplicationInvalidValue(_RPCSvrInvalidValue):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrInvalidValue.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProtocolInvalidValue(_RPCSvrInvalidValue):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrInvalidValue.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class RPCSvrLockDenied(RPCServerError):
    def __init__(self, origmsg, session_id, **kwargs):
        RPCServerError.__init__(
            self,
            origmsg,
            RPCERR_TYPE_PROTOCOL,
            RPCERR_TAG_LOCK_DENIED,
            info={'session-id': str(session_id)},
            **kwargs)


class RPCSvrMalformedMessage(RPCServerError):
    """
    If the server raises this exception the and netconf 1.0 is in use,
    the session will be closed
    """

    def __init__(self, origmsg):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_RPC, RPCERR_TAG_MALFORMED_MESSAGE)


# Backward compat
RPCSvrErrBadMsg = RPCSvrMalformedMessage


class _RPCSvrMissingAttribute(RPCServerError):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        RPCServerError.__init__(
            self,
            origmsg,
            etype,
            RPCERR_TAG_MISSING_ATTRIBUTE,
            info={'bad-element': element.tag,
                  'bad-attibute': attribute},
            **kwargs)


class RPCSvrApplicationMissingAttribute(_RPCSvrMissingAttribute):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _RPCSvrMissingAttribute.__init__(self, origmsg, element, attribute, RPCERR_TYPE_APPLICATION,
                                         **kwargs)


class RPCSvrProtocolMissingAttribute(_RPCSvrMissingAttribute):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _RPCSvrMissingAttribute.__init__(self, origmsg, element, attribute, RPCERR_TYPE_PROTOCOL,
                                         **kwargs)


class RPCSvrRPCMissingAttribute(_RPCSvrMissingAttribute):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _RPCSvrMissingAttribute.__init__(self, origmsg, element, attribute, RPCERR_TYPE_RPC,
                                         **kwargs)


class _RPCSvrMissingElement(RPCServerError):
    def __init__(self, origmsg, tag, etype, **kwargs):
        RPCServerError.__init__(
            self,
            origmsg,
            etype,
            RPCERR_TAG_MISSING_ELEMENT,
            info={'bad-element': str(tag)},
            **kwargs)


class RPCSvrApplicationMissingElement(_RPCSvrMissingElement):
    def __init__(self, origmsg, tag, **kwargs):
        _RPCSvrMissingElement.__init__(self, origmsg, tag, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProtocolMissingElement(_RPCSvrMissingElement):
    def __init__(self, origmsg, tag, **kwargs):
        _RPCSvrMissingElement.__init__(self, origmsg, tag, RPCERR_TYPE_PROTOCOL, **kwargs)


class _RPCSvrOperationFailed(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_OPERATION_FAILED, **kwargs)


class RPCSvrApplicationOperationFailed(_RPCSvrOperationFailed):
    def __init__(self, origmsg, etype, **kwargs):
        _RPCSvrOperationFailed.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProtocolOperationFailed(_RPCSvrOperationFailed):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrOperationFailed.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class RPCSvrRPCOperationFailed(_RPCSvrOperationFailed):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrOperationFailed.__init__(self, origmsg, RPCERR_TYPE_RPC, **kwargs)


class _RPCSvrOperationNotSupported(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_OPERATION_NOT_SUPPORTED, **kwargs)


class RPCSvrApplicationOperationNotSupported(_RPCSvrOperationNotSupported):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrOperationNotSupported.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProtocolOperationNotSupported(_RPCSvrOperationNotSupported):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrOperationNotSupported.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


# Backward compat
RPCSvrErrNotImpl = RPCSvrProtocolOperationNotSupported


class _RPCSvrResourceDenied(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_RESOURCE_DENIED, **kwargs)


class RPCSvrApplicationResourceDenied(_RPCSvrResourceDenied):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrResourceDenied.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProtocolResourceDenied(_RPCSvrResourceDenied):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrResourceDenied.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class RPCSvrRPCResourceDenied(_RPCSvrResourceDenied):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrResourceDenied.__init__(self, origmsg, RPCERR_TYPE_RPC, **kwargs)


class RPCSvrTransportResourceDenied(_RPCSvrResourceDenied):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrResourceDenied.__init__(self, origmsg, RPCERR_TYPE_TRANSPORT, **kwargs)


# # This is a pretty complex error if a server really supports it it can implement it itself.
# class RPCSvrPartialOperation(RPCServerError):
#     def __init__(self, origmsg, ok_elms, err_elms, noop_elms, **kwargs):
#         RPCServerError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION,
#                                 RPCERR_TAG_PARTIAL_OPERATION,
#                                 **kwargs)


class _RPCSvrRollbackFailed(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_ROLLBACK_FAILED, **kwargs)


class RPCSvrApplicationRollbackFailed(_RPCSvrRollbackFailed):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrRollbackFailed.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProtocolRollbackFailed(_RPCSvrRollbackFailed):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrRollbackFailed.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class _RPCSvrTooBig(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_TOO_BIG, **kwargs)


class RPCSvrApplicationTooBig(_RPCSvrTooBig):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrTooBig.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProtocolTooBig(_RPCSvrTooBig):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrTooBig.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class RPCSvrRPCTooBig(_RPCSvrTooBig):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrTooBig.__init__(self, origmsg, RPCERR_TYPE_RPC, **kwargs)


class RPCSvrTransportTooBig(_RPCSvrTooBig):
    def __init__(self, origmsg, **kwargs):
        _RPCSvrTooBig.__init__(self, origmsg, RPCERR_TYPE_TRANSPORT, **kwargs)


class _RPCSvrUnknownAttribute(RPCServerError):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        RPCServerError.__init__(
            self,
            origmsg,
            etype,
            RPCERR_TAG_UNKNOWN_ATTRIBUTE,
            info={'bad-element': element.tag,
                  'bad-attibute': attribute},
            **kwargs)


class RPCSvrApplicationUnknownAttribute(_RPCSvrUnknownAttribute):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        _RPCSvrUnknownAttribute.__init__(self, origmsg, element, attribute, RPCERR_TYPE_APPLICATION,
                                         **kwargs)


class RPCSvrProtocolUnknownAttribute(_RPCSvrUnknownAttribute):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        _RPCSvrUnknownAttribute.__init__(self, origmsg, element, attribute, RPCERR_TYPE_PROTOCOL,
                                         **kwargs)


class RPCSvrRPCUnknownAttribute(_RPCSvrUnknownAttribute):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        _RPCSvrUnknownAttribute.__init__(self, origmsg, element, attribute, RPCERR_TYPE_RPC,
                                         **kwargs)


class _RPCSvrUnknownElement(RPCServerError):
    def __init__(self, origmsg, element, etype, **kwargs):
        RPCServerError.__init__(
            self,
            origmsg,
            etype,
            RPCERR_TAG_UNKNOWN_ELEMENT,
            info={'bad-element': element.tag},
            **kwargs)


class RPCSvrApplicationUnknownElement(_RPCSvrUnknownElement):
    def __init__(self, origmsg, element, **kwargs):
        _RPCSvrUnknownElement.__init__(self, origmsg, element, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProtocolUnknownElement(_RPCSvrUnknownElement):
    def __init__(self, origmsg, element, **kwargs):
        _RPCSvrUnknownElement.__init__(self, origmsg, element, RPCERR_TYPE_PROTOCOL, **kwargs)


class _RPCSvrUnknownNamespace(RPCServerError):
    def __init__(self, origmsg, element, etype, **kwargs):
        try:
            qname = etree.QName(element.tag)
            tag = qname.localname
            ns = qname.namespace
        except Exception:
            tag = element.tag
            ns = "no namespace map"
        RPCServerError.__init__(
            self,
            origmsg,
            etype,
            RPCERR_TAG_UNKNOWN_NAMESPACE,
            info={'bad-element': tag,
                  'bad-namespace': ns},
            **kwargs)


class RPCSvrApplicationUnknownNamespace(_RPCSvrUnknownNamespace):
    def __init__(self, origmsg, element, etype, **kwargs):
        _RPCSvrUnknownNamespace.__init__(self, origmsg, element, RPCERR_TYPE_APPLICATION, **kwargs)


class RPCSvrProtocolUnknownNamespace(_RPCSvrUnknownNamespace):
    def __init__(self, origmsg, element, etype, **kwargs):
        _RPCSvrUnknownNamespace.__init__(self, origmsg, element, RPCERR_TYPE_PROTOCOL, **kwargs)


__author__ = 'Christian Hopps'
__date__ = 'February 19 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
