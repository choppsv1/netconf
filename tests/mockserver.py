# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# January 22 2018, Christian E. Hopps <chopps@gmail.com>
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
import getpass
import logging
from netconf import NSMAP, qmap
import netconf.util as ncutil
import netconf.error as ncerror
import netconf.server as ncserver

logger = logging.getLogger(__name__)
nc_server = None
NC_PORT = None
NC_DEBUG = False

mock_module = "urn:mock:module"


class MockMethods(object):
    NCFILTER = qmap("nc") + "filter"
    """This is an abstract class that is used to document the server methods functionality

    The server return not-implemented if the method is not found in the methods object,
    so feel free to use duck-typing here (i.e., no need to inherit)
    """

    def nc_append_capabilities(self, capabilities):  # pylint: disable=W0613
        """The server should append any capabilities it supports to capabilities"""
        ncutil.subelm(capabilities, "capability").text = mock_module

    def rpc_get(self, session, rpc, filter_or_none):  # pylint: disable=W0613
        data = ncutil.elm("data")
        cont = ncutil.subelm(data, "interfaces")
        listval = ncutil.subelm(cont, "interface")
        listval.append(ncutil.leaf_elm("name", "Ethernet0/0"))
        listval.append(ncutil.leaf_elm("shutdown", "true"))
        listval.append(ncutil.leaf_elm("state", "down"))
        listval = ncutil.subelm(cont, "interface")
        listval.append(ncutil.leaf_elm("name", "Ethernet0/1"))
        listval.append(ncutil.leaf_elm("shutdown", "false"))
        listval.append(ncutil.leaf_elm("state", "down"))
        listval = ncutil.subelm(cont, "interface")
        listval.append(ncutil.leaf_elm("name", "FastEthernet1/0"))
        listval.append(ncutil.leaf_elm("shutdown", "false"))
        listval.append(ncutil.leaf_elm("state", "up"))
        listval = ncutil.subelm(cont, "interface")
        listval.append(ncutil.leaf_elm("name", "FastEthernet1/1"))
        listval.append(ncutil.leaf_elm("shutdown", "false"))
        listval.append(ncutil.leaf_elm("state", "down"))
        return data

    def rpc_get_config(self, session, rpc, source_elm, filter_or_none):  # pylint: disable=W0613
        assert source_elm is not None
        if source_elm.find("nc:running", namespaces=NSMAP) is None:
            raise ncerror.RPCSvrMissingElement(rpc, ncutil.elm("nc:running"))

        config = ncutil.elm("config")
        cont = ncutil.subelm(config, "interfaces")
        listval = ncutil.subelm(cont, "interface")
        listval.append(ncutil.leaf_elm("name", "Ethernet0/0"))
        listval.append(ncutil.leaf_elm("shutdown", "true"))
        listval = ncutil.subelm(cont, "interface")
        listval.append(ncutil.leaf_elm("name", "Ethernet0/1"))
        listval.append(ncutil.leaf_elm("shutdown", "false"))
        listval = ncutil.subelm(cont, "interface")
        listval.append(ncutil.leaf_elm("name", "FastEthernet1/0"))
        listval.append(ncutil.leaf_elm("shutdown", "false"))
        listval = ncutil.subelm(cont, "interface")
        listval.append(ncutil.leaf_elm("name", "FastEthernet1/1"))
        listval.append(ncutil.leaf_elm("shutdown", "false"))
        # Missing from operational
        listval.append(ncutil.leaf_elm("name", "GigabitEthernet2/0"))
        listval.append(ncutil.leaf_elm("shutdown", "false"))
        return config

    #---------------------------------------------------------------------------
    # These definitions will change to include required parameters like get and
    # get-config
    #---------------------------------------------------------------------------

    # XXX The API WILL CHANGE consider unfinished
    def rpc_copy_config(self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # XXX The API WILL CHANGE consider unfinished
    def rpc_delete_config(self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # XXX The API WILL CHANGE consider unfinished
    def rpc_edit_config(self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # XXX The API WILL CHANGE consider unfinished
    def rpc_lock(self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)

    # XXX The API WILL CHANGE consider unfinished
    def rpc_unlock(self, unused_session, rpc, *unused_params):
        raise ncerror.RPCSvrErrNotImpl(rpc)


def init_mock_server():
    logging.basicConfig(level=logging.DEBUG)

    if init_mock_server.server is not None:
        logger.error("XXX Called init_mock_server called multiple times")
    else:
        sctrl = ncserver.SSHUserPassController(username=getpass.getuser(), password="admin")
        init_mock_server.server = ncserver.NetconfSSHServer(
            server_ctl=sctrl,
            server_methods=MockMethods(),
            port=None,
            host_key="tests/host_key",
            debug=NC_DEBUG)
    return init_mock_server.server.port


init_mock_server.server = None

__author__ = 'Christian E. Hopps'
__date__ = 'January 22 2018'
__version__ = '1.0'
__docformat__ = "restructuredtext en"
