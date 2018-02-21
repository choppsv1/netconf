# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# August 23 2017, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2017-2018, Deutsche Telekom AG
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
import logging
import os
import sys
import netconf.client as client
from lxml import etree


def parse_password_arg(password):
    if password:
        if password.startswith("env:"):
            unused, key = password.split(":", 1)
            password = os.environ[key]
        elif password.startswith("file:"):
            unused, path = password.split(":", 1)
            password = open(path).read().rstrip("\n")
    return password


def main(*margs):
    parser = argparse.ArgumentParser("Netconf Client Utility")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument('--host', default="localhost", help='Netconf server hostname')
    parser.add_argument(
        '--get',
        nargs='?',
        help="Perform <get>. arg value is xpath/xml filter or taken from infile if not specified")
    parser.add_argument(
        '--get-config',
        nargs='?',
        help=
        "Perform <get-config>. arg value is xpath/xml filter or taken from infile if not specified")
    parser.add_argument(
        '--hello', action="store_true", help="Do hello and return capabilities of server.")
    parser.add_argument("-i", "--infile", help="File to read from")
    parser.add_argument(
        '-p',
        '--password',
        default=None,
        help='Netconf password (use "env:" or "file:" prefix to specify source)')
    # Deprecated now parse password args more functional
    parser.add_argument('--passenv', default=None, help=argparse.SUPPRESS)
    parser.add_argument('--port', type=int, default=830, help='Netconf server port')
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet operation")
    parser.add_argument('--source', default="running", help="Source for get config")
    parser.add_argument('--timeout', type=float, help="Timeout for command in fractional seconds")
    parser.add_argument('-u', '--username', default="admin", help='Netconf username')
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args(*margs)

    if args.passenv and args.password:
        print("Only one of --password and --passenv allowed", file=sys.stderr)
        sys.exit(1)
    if args.passenv:
        args.password = os.environ[args.passenv]
    else:
        args.password = parse_password_arg(args.password)

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose:
        logging.basicConfig(level=logging.INFO)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.WARNING)

    session = client.NetconfSSHSession(
        args.host, args.port, args.username, args.password, debug=args.debug)

    if args.hello:
        result = "\n".join(session.capabilities) + "\n"
    elif args.get:
        result = session.get(args.get, args.timeout)
        result = etree.tounicode(result, pretty_print=True)
    elif args.get_config:
        result = session.get_config(args.source, args.get_config, args.timeout)
        result = etree.tounicode(result, pretty_print=True)
    else:
        if args.infile:
            xml = open(args.infile).read()
        else:
            xml = sys.stdin.read()
        if not xml:
            print("Nothing to do.", file=sys.stderr)
            sys.exit(1)
        result = session.send_rpc(xml)[2]
    sys.stdout.write(result)
    session.close()


if __name__ == "__main__":
    main()

__author__ = ''
__date__ = 'August 23 2017'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
