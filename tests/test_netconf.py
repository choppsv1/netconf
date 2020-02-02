# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# December 23 2014, Christian Hopps <chopps@gmail.com>
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
import logging
from lxml import etree

import netconf.client as client
from netconf.error import NetconfError
from mockserver import init_mock_server
from testutil import xml_eq

logger = logging.getLogger(__name__)
NC_PORT = None
NC_DEBUG = True


def setup_module(unused_module):
    global NC_PORT
    NC_PORT = init_mock_server()


def test_xpath_query(caplog):
    select = "/t:interfaces/t:interface[t:name='Ethernet0/0']/t:shutdown"

    caplog.set_level(logging.DEBUG)
    logger.info("Connecting to 127.0.0.1 port %d", NC_PORT)
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG)

    cmptree = etree.fromstring("""
        <data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <interfaces xmlns="urn:test:mock">
                <interface>
                    <shutdown>true</shutdown>
                </interface>
            </interfaces>
        </data>""")

    results = session.get(select)
    assert (xml_eq(results, cmptree))


def test_xpath_config_query():
    select = "/t:interfaces/t:interface[t:name='Ethernet0/1']"

    logger.info("Connecting to 127.0.0.1 port %d", NC_PORT)
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG)

    cmptree = etree.fromstring("""
        <data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <interfaces xmlns="urn:test:mock">
                <interface>
                    <name>Ethernet0/1</name>
                    <shutdown>false</shutdown>
                </interface>
            </interfaces>
        </data>""")

    results = session.get_config("running", select)
    assert (xml_eq(results, cmptree))


def test_xpath_query_multi():
    select = ("/t:interfaces/t:interface[t:name='Ethernet0/0']/t:state | " +
              "/t:interfaces/t:interface[t:name='Ethernet0/0']/t:shutdown")

    logger.info("Connecting to 127.0.0.1 port %d", NC_PORT)
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG)

    cmptree = etree.fromstring("""
        <data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <interfaces xmlns="urn:test:mock">
                <interface>
                    <shutdown>true</shutdown>
                    <state>down</state>
                </interface>
            </interfaces>
        </data>""")

    results = session.get(select)
    assert (xml_eq(results, cmptree))


def test_subtree_any_ns_query():
    select = """
        <interfaces>
        <interface>
        <name>Ethernet0/0</name>
        <state/>
        </interface>
        </interfaces>
        """

    logger.info("Connecting to 127.0.0.1 port %d", NC_PORT)
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG)

    cmptree = etree.fromstring("""
        <data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <interfaces xmlns="urn:test:mock">
                <interface>
                    <name>Ethernet0/0</name>
                    <state>down</state>
                </interface>
            </interfaces>
        </data>""")

    results = session.get(select)
    assert (xml_eq(results, cmptree))


def test_subtree_explicit_ns_query():
    select = """
        <foo:interfaces xmlns:foo="urn:test:mock">
        <foo:interface>
        <foo:name>Ethernet0/0</foo:name>
        <foo:state/>
        </foo:interface>
        </foo:interfaces>
        """

    logger.info("Connecting to 127.0.0.1 port %d", NC_PORT)
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG)

    cmptree = etree.fromstring("""
        <data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <interfaces xmlns="urn:test:mock">
                <interface>
                    <name>Ethernet0/0</name>
                    <state>down</state>
                </interface>
            </interfaces>
        </data>""")

    results = session.get(select)
    assert (xml_eq(results, cmptree))


def test_subtree_explicit_ns_query_elm():
    select = etree.fromstring("""
        <foo:interfaces xmlns:foo="urn:test:mock">
        <foo:interface>
        <foo:name>Ethernet0/0</foo:name>
        <foo:state/>
        </foo:interface>
        </foo:interfaces>
        """)

    logger.info("Connecting to 127.0.0.1 port %d", NC_PORT)
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG)

    cmptree = etree.fromstring("""
        <data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <interfaces xmlns="urn:test:mock">
                <interface>
                    <name>Ethernet0/0</name>
                    <state>down</state>
                </interface>
            </interfaces>
        </data>""")

    results = session.get(select)
    assert (xml_eq(results, cmptree))


def test_bad_query():
    session = client.NetconfSSHSession("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG)
    try:
        _, _, output = session.send_rpc("<get><unknown/></get>")
        logger.warning("Got unexpected output: %s", str(output))
    except NetconfError:
        pass


def test_context_manager():
    logger.info("Connecting to 127.0.0.1 port %d", NC_PORT)
    with client.connect_ssh("127.0.0.1", password="admin", port=NC_PORT, debug=NC_DEBUG) as session:
        _ = session.get()
        # print(etree.tostring(results))


__author__ = 'Christian Hopps'
__date__ = 'December 23 2014'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
