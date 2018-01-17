..
.. January 15 2018, Christian Hopps <chopps@gmail.com>
..

*****
Usage
*****


Command Line Tool
=================

To get the capabilities of a server:

.. code-block:: python

  $ netconf-client --hello --host example.com


To request config from a server that has your key:

.. code-block:: shell-script

  $ netconf-client --host example.com <<<"<get-config/>"


Development
===========

To use netconf in a project:

.. code-block:: python

  import netconf


Netconf Client
--------------

To open a session to server:

.. code-block:: python

  from netconf.client import NetconfSSHSession

  session = NetconfSSHSession(host, port, username, password)

To send and RPC to a server:

.. code-block:: python

  rpcout = session.send_rpc("<my-rpc/>")

Netconf Server
--------------

To create a simple server listening on port 830 that handles one RPC ``<my-cool-rpc>``:

.. code-block:: python

  from netconf import nsmap_update, server
  import netconf.util as ncutil

  MODEL_NS = "urn:my-urn:my-model"
  nsmap_update({'pfx': MODEL_NS})

  class MyServer (object):
      def __init__ (self, user, pw):
          controller = server.SSHUserPassController(username=user, password=pw)
          self.server = server.NetconfSSHServer(server_ctl=controller, server_methods=self)

      def nc_append_capabilities(self, caps):
          ncutil.subelm(caps, "capability").text = MODEL_NS

      def rpc_my_cool_rpc (self, session, rpc, *params):
          data = ncutil.elm("data")
          data.append(ncutil.leaf_elm("pfx:result", "RPC result string"))
          return data

  # ...
  server = MyServer("myuser", "mysecert")
  # ...
