# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# February 19 2015, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2015, Deutsche Telekom AG
# Copyright (c) 2019 by Christian E. Hopps.
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
import io
import socket
import sys
import threading
import traceback
from lxml import etree

from netconf import NSMAP, MAXSSHBUF
from netconf.error import ChannelClosed, FramingError, SessionError
import netconf.util as ncutil

logger = logging.getLogger(__name__)

NC_BASE_10 = "urn:ietf:params:netconf:base:1.0"
NC_BASE_11 = "urn:ietf:params:netconf:base:1.1"
XML_HEADER = """<?xml version="1.0" encoding="UTF-8"?>"""

if sys.version_info[0] >= 3:

    def lookahead(iterable):
        """Return an element and an indication if it's the last element"""
        i = iter(iterable)
        last = next(i)
        for e in i:
            yield last, False
            last = e
        yield last, True
else:

    def lookahead(iterable):
        """Return an element and an indication if it's the last element"""
        i = iter(iterable)
        last = i.next()
        for e in i:
            yield last, False
            last = e
        yield last, True


def chunkit(msg, maxsend, minsend=0, pad="\n"):
    """
    chunkit iterates over a msg returning chunks of at most maxsend
    size, and of at least minsend size if non-zero. Padding will be
    added if required. This function currently requires that maxsend
    is at least large enough to hold 2 minsend chunks.
    """
    # For now we'll make this assumption as it makes the
    # implementation much easier.
    assert maxsend >= 2 * minsend

    sz = len(msg)
    nchunks = sz // maxsend
    lastmax = sz % maxsend

    # Handle the special cases
    if sz == 0:
        return
    elif nchunks == 1 and lastmax == 0:
        yield msg
        return
    elif nchunks == 0:
        # lastmax == 0 then sz == 0 handled above.
        assert lastmax != 0
        if lastmax < minsend:
            msg = msg + pad * (minsend - lastmax)
        yield msg
        return

    # Make sure our final chunk is at least minsend long.
    nchunks -= 1
    penultmax = maxsend
    if lastmax == 0:
        lastmax = maxsend
        nchunks -= 1
    elif lastmax < minsend:
        penultmax -= minsend - lastmax
        lastmax = minsend

    left = 0
    for unused in range(0, nchunks):
        yield msg[left:left + maxsend]
        left += maxsend

    right = left + penultmax
    yield msg[left:right]
    yield msg[right:]


class NetconfTransportMixin(object):
    def connect(self):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()


class NetconfPacketTransport(object):
    def send_pdu(self, msg, new_framing):
        raise NotImplementedError()

    def receive_pdu(self, new_framing):
        raise NotImplementedError()


class NetconfFramingTransport(NetconfPacketTransport):
    """Packetize an ssh stream into netconf PDUs -- doesn't need to be SSH specific"""

    def __init__(self, stream, max_chunk, debug):
        # XXX we have 2 channels defined one here and one in the connect/accept class
        self.stream = stream
        self.max_chunk = max_chunk
        self.debug = debug
        self.rbuffer = b""

    def __del__(self):
        self.close()

    def close(self):
        stream = self.stream
        if stream is not None:
            self.stream = None
            if self.debug:
                logger.debug("Closing netconf socket stream %s", str(stream))
            stream.close()

    def is_active(self):
        try:
            self.stream.is_active
        except AttributeError:
            transport = self.stream.get_transport()
            if not transport:
                return False
            return transport.is_active()
        else:
            return self.stream.is_active()

    def receive_pdu(self, new_framing):
        assert self.stream is not None
        if new_framing:
            return self._receive_11()
        else:
            return self._receive_10()

    def send_pdu(self, msg, new_framing):
        assert self.stream is not None
        if new_framing:
            bmsg = msg.encode('utf-8')
            blen = len(bmsg)
            msg = "\n#{}\n".format(blen).encode('utf-8') + bmsg + "\n##\n".encode('utf-8')
        else:
            msg += "]]>]]>"

        # Apparently ssh has a bug that requires minimum of 64 bytes?
        for chunk in chunkit(msg, self.max_chunk, 64):
            self.stream.sendall(chunk)

    def _receive_10(self):
        searchfrom = 0
        while True:
            eomidx = self.rbuffer.find(b"]]>]]>", searchfrom)
            if eomidx != -1:
                break
            searchfrom = max(0, len(self.rbuffer) - 5)
            buf = self.stream.recv(self.max_chunk)
            self.rbuffer += buf

        msg = self.rbuffer[:eomidx]
        self.rbuffer = self.rbuffer[eomidx + 6:]
        return msg.decode('utf-8')

    def _receive_chunk(self):
        blen = len(self.rbuffer)
        while blen < 4:
            buf = self.stream.recv(self.max_chunk)
            self.rbuffer += buf
            blen = len(self.rbuffer)
            if self.stream is None:
                if self.debug:
                    logger.debug("Channel closed: stream is None")
                raise ChannelClosed(self)
            if not buf:
                if self.debug:
                    logger.debug("Channel closed: Zero bytes read")
                raise ChannelClosed(self)

        if self.rbuffer[:2] != b"\n#":
            raise FramingError(self.rbuffer)
        self.rbuffer = self.rbuffer[2:]

        # Get chunk length or termination indicator
        idx = -1
        searchfrom = 0
        while True:
            idx = self.rbuffer.find(b"\n", searchfrom)
            if 12 > idx > 0:
                break
            if idx > 12 or len(self.rbuffer) > 12:
                raise FramingError(self.rbuffer)
            searchfrom = len(self.rbuffer)
            self.rbuffer += self.stream.recv(self.max_chunk)

        # Check for last chunk.
        if self.rbuffer[0:2] == b"#\n":
            self.rbuffer = self.rbuffer[2:]
            return None

        lenstr = self.rbuffer[:idx]
        self.rbuffer = bytes(self.rbuffer[idx + 1:])

        try:
            chunklen = int(lenstr)
            if not (4294967295 >= chunklen > 0):
                raise FramingError("Unacceptable chunk length: {}".format(chunklen))
        except ValueError:
            raise FramingError("Frame length not integer: {}".format(lenstr.encode('utf-8')))

        while True:
            blen = len(self.rbuffer)
            if blen >= chunklen:
                chunk = self.rbuffer[:chunklen]
                self.rbuffer = self.rbuffer[chunklen:]
                return chunk
            self.rbuffer += self.stream.recv(self.max_chunk)

    def _iter_receive_chunks(self):
        assert self.stream is not None
        chunk = self._receive_chunk()
        while chunk:
            yield chunk
            chunk = self._receive_chunk()

    def _receive_11(self):
        assert self.stream is not None
        data = b"".join([x for x in self._iter_receive_chunks()])
        return data.decode('utf-8')


class NetconfSession(object):
    """Netconf Protocol Server and Client"""

    # This class is almost idntical to sshutil.SSHServerSession We need to
    # figure a way to factor the commonality. One issue is that this class can
    # be used with any transport not just SSH so where should it go?

    def __init__(self, stream, debug, session_id, max_chunk=MAXSSHBUF):
        self.debug = debug
        self.pkt_stream = NetconfFramingTransport(stream, max_chunk, debug)
        self.new_framing = False
        self.capabilities = set()
        self.reader_thread = None
        self.slock = threading.Lock()
        self.session_id = session_id
        self.session_open = False

    def __del__(self):
        if hasattr(self, "session_open") and self.session_open:
            self.close()

    def is_active(self):
        with self.slock:
            return self.pkt_stream and self.pkt_stream.is_active()

    def __str__(self):
        return "NetconfSession(sid:{})".format(self.session_id)

    def send_message(self, msg):
        with self.slock:
            pkt_stream = self.pkt_stream
        if not pkt_stream:
            logger.info("Dropping message b/c no connection stream (%d): %s", len(msg), msg)
            return
        if self.debug:
            logger.debug("Sending message (%d): %s", len(msg), msg)
        pkt_stream.send_pdu(XML_HEADER + msg, self.new_framing)

    def _receive_message(self):
        # private method to receive a full message.
        with self.slock:
            if self.reader_thread and not self.reader_thread.keep_running:
                return None
            pkt_stream = self.pkt_stream
        return pkt_stream.receive_pdu(self.new_framing)

    def send_hello(self, caplist, session_id=None):
        msg = ncutil.elm("hello", attrib={'xmlns': NSMAP['nc']})
        caps = ncutil.elm("capabilities")
        for cap in caplist:
            ncutil.subelm(caps, "capability").text = str(cap)
        if session_id is not None:
            assert hasattr(self, "methods")
            self.methods.nc_append_capabilities(caps)  # pylint: disable=E1101
        msg.append(caps)

        if self.debug:
            logger.debug("%s: Sending HELLO", str(self))
        if session_id is not None:
            msg.append(ncutil.leaf_elm("session-id", str(session_id)))
        msg = etree.tostring(msg)
        self.send_message(msg.decode('utf-8'))

    def close(self):
        if self.debug:
            logger.debug("%s: Closing.", str(self))

        with self.slock:
            if self.session_open:
                self.session_open = False
                self.session_id = None

            if self.reader_thread:
                self.reader_thread.keep_running = False

            if self.pkt_stream is not None:
                if self.debug:
                    logger.debug("%s: Closing transport.", str(self))

                pkt_stream = self.pkt_stream
                self.pkt_stream = None

                if pkt_stream:
                    # If we are blocked on reading this should unblock us
                    pkt_stream.close()

    def _open_session(self, is_server):
        assert is_server or self.session_id is None

        # The transport should be connected at this point.
        try:
            # Send hello message.
            self.send_hello((NC_BASE_10, NC_BASE_11), self.session_id)

            # Get reply
            reply = self._receive_message()
            if self.debug:
                logger.debug("Received HELLO")

            # Parse reply
            tree = etree.parse(io.BytesIO(reply.encode('utf-8')))
            root = tree.getroot()
            caps = root.xpath("//nc:hello/nc:capabilities/nc:capability", namespaces=NSMAP)

            # Store capabilities
            for cap in caps:
                self.capabilities.add(cap.text.strip())

            if NC_BASE_11 in self.capabilities:
                self.new_framing = True
            elif NC_BASE_10 not in self.capabilities:
                who = "Server" if is_server else "Client"
                raise SessionError("{} doesn't implement 1.0 or 1.1 of netconf".format(who))

            # Get session ID.
            try:
                session_id = root.xpath("//nc:hello/nc:session-id", namespaces=NSMAP)[0].text
                # If we are a server it is a failure to receive a session id.
                if is_server:
                    raise SessionError("Client sent a session-id")
                self.session_id = int(session_id)
            except (KeyError, IndexError, AttributeError):
                if not is_server:
                    raise SessionError("Server didn't supply session-id")
            except ValueError:
                raise SessionError("Server supplied non integer session-id: {}".format(session_id))

            self.session_open = True

            # Create reader thread.
            self.reader_thread = threading.Thread(target=self._read_message_thread)
            self.reader_thread.daemon = True
            self.reader_thread.keep_running = True
            self.reader_thread.start()

            if self.debug:
                logger.debug("%s: Opened version %s session.", str(self), "1.1"
                             if self.new_framing else "1.0")

        except Exception:
            self.close()
            raise

    def _reader_exits(self):
        """This function is called from the session reader thread as it exits. No more
        messages will be read from the session socket.
        """
        raise NotImplementedError("reader_exits")

    def _reader_handle_message(self, msg):
        """This function is called from the session reader thread to process a received
        framed netconf message.
        """
        # Called from reader thread after receiving a framed message
        raise NotImplementedError("read_handle_message")

    def _read_message_thread(self):
        # XXX the locking and dealing with the exit of this thread needs improvement
        if self.debug:
            logger.debug("Starting reader thread.")

        reader_thread = self.reader_thread
        try:
            while self.pkt_stream:
                with self.slock:
                    pkt_stream = self.pkt_stream
                    if not reader_thread.keep_running:
                        break
                    assert pkt_stream is not None

                msg = self._receive_message()
                if msg:
                    self._reader_handle_message(msg)
                    closed = False
                else:
                    # Client closed, never really see this 1/2 open case unfortunately.
                    if self.debug:
                        logger.debug("Client remote closed, exiting reader thread.")
                    closed = True

                with self.slock:
                    if closed:
                        reader_thread.keep_running = False
                    if not reader_thread.keep_running:
                        break

            if self.debug:
                logger.debug("Exiting reader thread")

        except AttributeError as error:
            # Should we close the session cleanly or just disconnect?
            if "'NoneType' object has no attribute 'recv'" in str(error):
                logger.error("%s: Session channel cleared (open: %s): %s: %s", str(self),
                             str(self.session_open), str(error), traceback.format_exc())
            else:
                logger.error(
                    "Unexpected exception in reader thread [disconnecting+exiting]: %s: %s",
                    str(error), traceback.format_exc())
            self.close()
        except ChannelClosed as error:
            # Should we close the session cleanly or just disconnect?
            # if self.debug:
            #     logger.debug("%s: Session channel closed [session_open == %s]: %s: %s",
            #                  str(self),
            #                  str(self.session_open),
            #                  str(error),
            #                  traceback.format_exc())
            # else:
            logger.debug("%s: Session channel closed [session_open == %s]: %s", str(self),
                         str(self.session_open), str(error))
            try:
                self.close()
            except Exception as error:
                logger.debug("%s: Exception while closing during ChannelClosed: %s", str(self),
                             str(error))
        except SessionError as error:
            # Should we close the session cleanly or just disconnect?
            logger.error("%s Session error [closing session]: %s", str(self), str(error))
            self.close()
        except socket.error as error:
            if self.debug:
                logger.debug("Socket error in reader thread [exiting]: %s", str(error))
            self.close()
        except Exception as error:
            with self.slock:
                keep_running = reader_thread.keep_running
            if keep_running:
                logger.error(
                    "Unexpected exception in reader thread [disconnecting+exiting]: %s: %s",
                    str(error), traceback.format_exc())
                self.close()
            else:
                # XXX might want to catch errors due to disconnect and not re-raise
                logger.debug("Exception in reader thread [exiting]: %s: %s", str(error),
                             traceback.format_exc())
        finally:
            # If we are exiting the read thread we close the session.
            self._reader_exits()


__author__ = 'Christian Hopps'
__date__ = 'December 23 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
