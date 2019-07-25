# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# February 24 2018, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2018, Deutsche Telekom AG.
# All Rights Reserved.
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
import argparse
import datetime
import logging
import os
import platform
import socket
import sys
import time
from netconf import error, server, util
from netconf import nsmap_add, NSMAP

nsmap_add("sys", "urn:ietf:params:xml:ns:yang:ietf-system")


def parse_password_arg(password):
    if password:
        if password.startswith("env:"):
            unused, key = password.split(":", 1)
            password = os.environ[key]
        elif password.startswith("file:"):
            unused, path = password.split(":", 1)
            password = open(path).read().rstrip("\n")
    return password


def date_time_string(dt):
    tz = dt.strftime("%z")
    s = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
    if tz:
        s += " {}:{}".format(tz[:-2], tz[-2:])
    return s


class SystemServer(object):
    def __init__(self, port, host_key, auth, debug):
        self.server = server.NetconfSSHServer(auth, self, port, host_key, debug)

    def close():
        self.server.close()

    def nc_append_capabilities(self, capabilities):  # pylint: disable=W0613
        """The server should append any capabilities it supports to capabilities"""
        util.subelm(capabilities,
                    "capability").text = "urn:ietf:params:netconf:capability:xpath:1.0"
        util.subelm(capabilities, "capability").text = NSMAP["sys"]

    def _add_config (self, data):
        sysc = util.subelm(data, "sys:system")

        # System Identification
        sysc.append(util.leaf_elm("sys:hostname", socket.gethostname()))

        # System Clock
        clockc = util.subelm(sysc, "sys:clock")
        tzname = time.tzname[time.localtime().tm_isdst]
        clockc.append(util.leaf_elm("sys:timezone-utc-offset", int(time.timezone / 100)))

    def rpc_get(self, session, rpc, filter_or_none):  # pylint: disable=W0613
        """Passed the filter element or None if not present"""
        data = util.elm("nc:data")

        #
        # Config Data
        #

        self._add_config(data)

        #
        # State Data
        #
        sysd = util.subelm(data, "sys:system-state")

        # System Identification
        platc = util.subelm(sysd, "sys:platform")
        platc.append(util.leaf_elm("sys:os-name", platform.system()))
        platc.append(util.leaf_elm("sys:os-release", platform.release()))
        platc.append(util.leaf_elm("sys:os-version", platform.version()))
        platc.append(util.leaf_elm("sys:machine", platform.machine()))

        # System Clock
        clockc = util.subelm(sysd, "sys:clock")
        now = datetime.datetime.now()
        clockc.append(util.leaf_elm("sys:current-datetime", date_time_string(now)))

        if os.path.exists("/proc/uptime"):
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
            boottime = time.time() - uptime_seconds
            boottime = datetime.datetime.fromtimestamp(boottime)
            clockc.append(util.leaf_elm("sys:boot-datetime", date_time_string(boottime)))

        return util.filter_results(rpc, data, filter_or_none, self.server.debug)

    def rpc_get_config(self, session, rpc, source_elm, filter_or_none):  # pylint: disable=W0613
        """Passed the source element"""
        data = util.elm("nc:data")
        #
        # Config Data
        #
        self._add_config(data)
        return util.filter_results(rpc, data, filter_or_none)

    def rpc_system_restart(self, session, rpc, *params):
        raise error.AccessDeniedAppError(rpc)

    def rpc_system_shutdown(self, session, rpc, *params):
        raise error.AccessDeniedAppError(rpc)


def main(*margs):

    parser = argparse.ArgumentParser("Example System Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--password", default="admin", help='Use "env:" or "file:" prefix to specify source')
    parser.add_argument('--port', type=int, default=8300, help='Netconf server port')
    parser.add_argument("--username", default="admin", help='Netconf username')
    args = parser.parse_args(*margs)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    args.password = parse_password_arg(args.password)
    host_key = os.path.join(os.path.abspath(os.path.dirname(__file__)), "server-key")

    auth = server.SSHUserPassController(username=args.username, password=args.password)
    s = SystemServer(args.port, host_key, auth, args.debug)

    if sys.stdout.isatty():
        print("^C to quit server")
    try:
        while True:
            time.sleep(1)
    except Exception:
        print("quitting server")

    s.close()


if __name__ == "__main__":
    main()

__author__ = 'Christian Hopps'
__date__ = 'February 24 2018'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
