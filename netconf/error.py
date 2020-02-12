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
from netconf import NSMAP, qmap


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


class NetconfError(NetconfException):
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


# Backward compatible
RPCError = NetconfError

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

# ============================================
# Server Errors for returning value to client.
# ============================================


class RPCServerError(NetconfException):
    def __init__(self, origmsg, etype, tag, **kwargs):
        # Add attrib and nsmap from original message.
        self.reply = etree.Element(qmap("nc") + "rpc-reply",
                                   attrib=origmsg.attrib,
                                   nsmap=origmsg.nsmap)

        rpcerr = etree.SubElement(self.reply, qmap("nc") + "rpc-error")

        # We require a type, tag, and severity assuming error for severity.
        if etype in RPCERR_TYPE_ENUM:
            etype = RPCERR_TYPE_ENUM[etype]
        etree.SubElement(rpcerr, qmap("nc") + "error-type").text = str(etype)

        etree.SubElement(rpcerr, qmap("nc") + "error-tag").text = tag

        if "severity" not in kwargs:
            etree.SubElement(rpcerr, qmap("nc") + "error-severity").text = "error"

        # Now convert any other arguments to xml
        for key, value in kwargs.items():
            # Allow info to be a dictionary we convert to sub-elements
            if key == "info" and hasattr(value, "items"):
                infoelm = etree.SubElement(rpcerr, qmap("nc") + "error-info")
                for ikey, ivalue in value.items():
                    ikey = ikey.replace('_', '-')
                    etree.SubElement(infoelm, "{}".format(ikey)).text = str(ivalue)
            else:
                key = key.replace('_', '-')
                etree.SubElement(rpcerr, qmap("nc") + "error-{}".format(key)).text = str(value)

        # This sort of sucks for humans
        super(RPCServerError, self).__init__(self.get_reply_msg())

    def get_reply_msg(self):
        return etree.tounicode(self.reply)


class RPCSvrException(RPCServerError):
    def __init__(self, origmsg, exception, **kwargs):
        RPCServerError.__init__(self,
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


class _AccessDeniedError(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_ACCESS_DENIED, **kwargs)


class AccessDeniedAppError(_AccessDeniedError):
    def __init__(self, origmsg, **kwargs):
        _AccessDeniedError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class AccessDeniedProtoError(_AccessDeniedError):
    def __init__(self, origmsg, **kwargs):
        _AccessDeniedError.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class _BadAttributeError(RPCServerError):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        RPCServerError.__init__(self,
                                origmsg,
                                etype,
                                RPCERR_TAG_BAD_ATTRIBUTE,
                                info={
                                    'bad-element': element.tag,
                                    'bad-attibute': attribute
                                },
                                **kwargs)


class BadAttributeAppError(_BadAttributeError):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _BadAttributeError.__init__(self, origmsg, element, attribute, RPCERR_TYPE_APPLICATION,
                                    **kwargs)


class BadAttributeProtoError(_BadAttributeError):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _BadAttributeError.__init__(self, origmsg, element, attribute, RPCERR_TYPE_PROTOCOL,
                                    **kwargs)


class BadAttributeRPCError(_BadAttributeError):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _BadAttributeError.__init__(self, origmsg, element, attribute, RPCERR_TYPE_RPC, **kwargs)


class _BadElementError(RPCServerError):
    def __init__(self, origmsg, element, etype, **kwargs):
        RPCServerError.__init__(self,
                                origmsg,
                                etype,
                                RPCERR_TAG_BAD_ELEMENT,
                                info={'bad-element': element.tag},
                                **kwargs)


class BadElementAppError(_BadElementError):
    def __init__(self, origmsg, element, **kwargs):
        _BadElementError.__init__(self, origmsg, element, RPCERR_TYPE_APPLICATION, **kwargs)


class BadElementProtoError(_BadElementError):
    def __init__(self, origmsg, element, **kwargs):
        _BadElementError.__init__(self, origmsg, element, RPCERR_TYPE_PROTOCOL, **kwargs)


class DataExistsAppError(RPCServerError):
    def __init__(self, origmsg, **kwargs):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, RPCERR_TAG_DATA_EXISTS,
                                **kwargs)


class DataMissingAppError(RPCServerError):
    def __init__(self, origmsg, **kwargs):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, RPCERR_TAG_DATA_MISSING,
                                **kwargs)


class _InvalidValueError(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_INVALID_VALUE, **kwargs)


class InvalidValueAppError(_InvalidValueError):
    def __init__(self, origmsg, **kwargs):
        _InvalidValueError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class InvalidValueProtoError(_InvalidValueError):
    def __init__(self, origmsg, **kwargs):
        _InvalidValueError.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class LockDeniedProtoError(RPCServerError):
    def __init__(self, origmsg, session_id, **kwargs):
        RPCServerError.__init__(self,
                                origmsg,
                                RPCERR_TYPE_PROTOCOL,
                                RPCERR_TAG_LOCK_DENIED,
                                info={'session-id': str(session_id)},
                                **kwargs)


class MalformedMessageRPCError(RPCServerError):
    """
    If the server raises this exception the and netconf 1.0 is in use,
    the session will be closed
    """
    def __init__(self, origmsg):
        RPCServerError.__init__(self, origmsg, RPCERR_TYPE_RPC, RPCERR_TAG_MALFORMED_MESSAGE)


class _MissingAttributeError(RPCServerError):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        RPCServerError.__init__(self,
                                origmsg,
                                etype,
                                RPCERR_TAG_MISSING_ATTRIBUTE,
                                info={
                                    'bad-element': element.tag,
                                    'bad-attibute': attribute
                                },
                                **kwargs)


class MissingAttributeAppError(_MissingAttributeError):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _MissingAttributeError.__init__(self, origmsg, element, attribute, RPCERR_TYPE_APPLICATION,
                                        **kwargs)


class MissingAttributeProtoError(_MissingAttributeError):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _MissingAttributeError.__init__(self, origmsg, element, attribute, RPCERR_TYPE_PROTOCOL,
                                        **kwargs)


class MissingAttributeRPCError(_MissingAttributeError):
    def __init__(self, origmsg, element, attribute, **kwargs):
        _MissingAttributeError.__init__(self, origmsg, element, attribute, RPCERR_TYPE_RPC,
                                        **kwargs)


class _MissingElementError(RPCServerError):
    def __init__(self, origmsg, tag, etype, **kwargs):
        RPCServerError.__init__(self,
                                origmsg,
                                etype,
                                RPCERR_TAG_MISSING_ELEMENT,
                                info={'bad-element': str(tag)},
                                **kwargs)


class MissingElementAppError(_MissingElementError):
    def __init__(self, origmsg, tag, **kwargs):
        _MissingElementError.__init__(self, origmsg, tag, RPCERR_TYPE_APPLICATION, **kwargs)


class MissingElementProtoError(_MissingElementError):
    def __init__(self, origmsg, tag, **kwargs):
        _MissingElementError.__init__(self, origmsg, tag, RPCERR_TYPE_PROTOCOL, **kwargs)


class _OperationFailedError(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_OPERATION_FAILED, **kwargs)


class OperationFailedAppError(_OperationFailedError):
    def __init__(self, origmsg, etype, **kwargs):
        _OperationFailedError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class OperationFailedProtoError(_OperationFailedError):
    def __init__(self, origmsg, **kwargs):
        _OperationFailedError.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class OperationFailedRPCError(_OperationFailedError):
    def __init__(self, origmsg, **kwargs):
        _OperationFailedError.__init__(self, origmsg, RPCERR_TYPE_RPC, **kwargs)


class _OperationNotSupportedError(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_OPERATION_NOT_SUPPORTED, **kwargs)


class OperationNotSupportedAppError(_OperationNotSupportedError):
    def __init__(self, origmsg, **kwargs):
        _OperationNotSupportedError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class OperationNotSupportedProtoError(_OperationNotSupportedError):
    def __init__(self, origmsg, **kwargs):
        _OperationNotSupportedError.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


# # This is a pretty complex error if a server really supports it it can implement it itself.
# class _PartialOperationError(RPCServerError):
#     def __init__(self, origmsg, ok_elms, err_elms, noop_elms, **kwargs):
#         RPCServerError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION,
#                                 RPCERR_TAG_PARTIAL_OPERATION,
#                                 **kwargs)


class _ResourceDeniedError(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_RESOURCE_DENIED, **kwargs)


class ResourceDeniedAppError(_ResourceDeniedError):
    def __init__(self, origmsg, **kwargs):
        _ResourceDeniedError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class ResourceDeniedProtoError(_ResourceDeniedError):
    def __init__(self, origmsg, **kwargs):
        _ResourceDeniedError.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class ResourceDeniedRPCError(_ResourceDeniedError):
    def __init__(self, origmsg, **kwargs):
        _ResourceDeniedError.__init__(self, origmsg, RPCERR_TYPE_RPC, **kwargs)


class ResourceDeniedTransportError(_ResourceDeniedError):
    def __init__(self, origmsg, **kwargs):
        _ResourceDeniedError.__init__(self, origmsg, RPCERR_TYPE_TRANSPORT, **kwargs)


class _RollbackFailedError(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_ROLLBACK_FAILED, **kwargs)


class RollbackFailedAppError(_RollbackFailedError):
    def __init__(self, origmsg, **kwargs):
        _RollbackFailedError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class RollbackFailedProtoError(_RollbackFailedError):
    def __init__(self, origmsg, **kwargs):
        _RollbackFailedError.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class _TooBigError(RPCServerError):
    def __init__(self, origmsg, etype, **kwargs):
        RPCServerError.__init__(self, origmsg, etype, RPCERR_TAG_TOO_BIG, **kwargs)


class TooBigAppError(_TooBigError):
    def __init__(self, origmsg, **kwargs):
        _TooBigError.__init__(self, origmsg, RPCERR_TYPE_APPLICATION, **kwargs)


class TooBigProtoError(_TooBigError):
    def __init__(self, origmsg, **kwargs):
        _TooBigError.__init__(self, origmsg, RPCERR_TYPE_PROTOCOL, **kwargs)


class TooBigRPCError(_TooBigError):
    def __init__(self, origmsg, **kwargs):
        _TooBigError.__init__(self, origmsg, RPCERR_TYPE_RPC, **kwargs)


class TooBigTransportError(_TooBigError):
    def __init__(self, origmsg, **kwargs):
        _TooBigError.__init__(self, origmsg, RPCERR_TYPE_TRANSPORT, **kwargs)


class _UnknownAttributeError(RPCServerError):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        RPCServerError.__init__(self,
                                origmsg,
                                etype,
                                RPCERR_TAG_UNKNOWN_ATTRIBUTE,
                                info={
                                    'bad-element': element.tag,
                                    'bad-attibute': attribute
                                },
                                **kwargs)


class UnknownAttributeAppError(_UnknownAttributeError):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        _UnknownAttributeError.__init__(self, origmsg, element, attribute, RPCERR_TYPE_APPLICATION,
                                        **kwargs)


class UnknownAttributeProtoError(_UnknownAttributeError):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        _UnknownAttributeError.__init__(self, origmsg, element, attribute, RPCERR_TYPE_PROTOCOL,
                                        **kwargs)


class UnknownAttributeRPCError(_UnknownAttributeError):
    def __init__(self, origmsg, element, attribute, etype, **kwargs):
        _UnknownAttributeError.__init__(self, origmsg, element, attribute, RPCERR_TYPE_RPC,
                                        **kwargs)


class _UnknownElementError(RPCServerError):
    def __init__(self, origmsg, element, etype, **kwargs):
        RPCServerError.__init__(self,
                                origmsg,
                                etype,
                                RPCERR_TAG_UNKNOWN_ELEMENT,
                                info={'bad-element': element.tag},
                                **kwargs)


class UnknownElementAppError(_UnknownElementError):
    def __init__(self, origmsg, element, **kwargs):
        _UnknownElementError.__init__(self, origmsg, element, RPCERR_TYPE_APPLICATION, **kwargs)


class UnknownElementProtoError(_UnknownElementError):
    def __init__(self, origmsg, element, **kwargs):
        _UnknownElementError.__init__(self, origmsg, element, RPCERR_TYPE_PROTOCOL, **kwargs)


class _UnknownNamespaceError(RPCServerError):
    def __init__(self, origmsg, element, etype, **kwargs):
        try:
            qname = etree.QName(element.tag)
            tag = qname.localname
            ns = qname.namespace
        except Exception:
            tag = element.tag
            ns = "no namespace map"
        RPCServerError.__init__(self,
                                origmsg,
                                etype,
                                RPCERR_TAG_UNKNOWN_NAMESPACE,
                                info={
                                    'bad-element': tag,
                                    'bad-namespace': ns
                                },
                                **kwargs)


class UnknownNamespaceAppError(_UnknownNamespaceError):
    def __init__(self, origmsg, element, etype, **kwargs):
        _UnknownNamespaceError.__init__(self, origmsg, element, RPCERR_TYPE_APPLICATION, **kwargs)


class UnknownNamespaceProtoError(_UnknownNamespaceError):
    def __init__(self, origmsg, element, etype, **kwargs):
        _UnknownNamespaceError.__init__(self, origmsg, element, RPCERR_TYPE_PROTOCOL, **kwargs)


# Backward compat -- XXX need some deprecation warning for these.
RPCSvrBadElement = BadElementAppError
RPCSvrErrNotImpl = OperationNotSupportedProtoError
RPCSvrErrBadMsg = MalformedMessageRPCError
RPCSvrInvalidValue = InvalidValueProtoError
RPCSvrMissingElement = MissingElementAppError
RPCSvrUnknownElement = UnknownElementAppError

__author__ = 'Christian Hopps'
__date__ = 'February 19 2015'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
