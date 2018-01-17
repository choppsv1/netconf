# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# August 23 2017, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2017, Deutsche Telekom AG.
# All Rights Reserved.
#

from __future__ import absolute_import, division, unicode_literals, print_function, nested_scopes

import argparse
import logging
import os
import sys
import netconf.client as client


def main(*margs):
    parser = argparse.ArgumentParser("Netconf Client Utility")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument('--host', default="localhost", help='Netconf server hostname')
    parser.add_argument('--port', default="830", help='Netconf server port')
    parser.add_argument(
        '--hello', action="store_true", help="Do hello and return capabilities of server.")
    parser.add_argument("-i", "--infile", help="File to read from")
    parser.add_argument('-p', '--password', default=None, help='Netconf password')
    parser.add_argument(
        '--passenv', default=None, help='Environment variable holding Cassandra password')
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet operation")
    parser.add_argument('-u', '--username', default="admin", help='Netconf username')
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args(*margs)

    if args.passenv and args.password:
        print("Only one of --password and --passenv allowed", file=sys.stderr)
        sys.exit(1)
    if args.passenv:
        args.password = os.environ[args.passenv]

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
        print("\n".join(session.capabilities))
        sys.exit(0)

    if args.infile:
        xml = open(args.infile).read()
    else:
        xml = sys.stdin.read()
    result = session.send_rpc(xml)
    sys.stdout.write(result[2])
    session.close()


if __name__ == "__main__":
    main()

__author__ = ''
__date__ = 'August 23 2017'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
