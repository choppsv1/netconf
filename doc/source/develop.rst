..
.. January 15 2018, Christian Hopps <chopps@gmail.com>
..

*****************
Development Usage
*****************

Netconf Client
==============

Sessions
--------

To open a session to server:

.. code-block:: python

  from netconf.client import NetconfSSHSession

  session = NetconfSSHSession(host, port, username, password)
  config = session.get_config()
  # ...

To open a session with a context manager:

.. code-block:: python

  from netconf.client import connect_ssh

  with connect_ssh(host, port, username, password) as session:
      config = session.get_config()
      # ...

To close a session:

.. code-block:: python

  session.close()

State
-----
To get the operational state from a server:

.. code-block:: python

  config = session.get()

To get a specific selection of state using xpath from a server:

.. code-block:: python

  config = session.get(select="/devices/device[name='RouterA']")

To get a specific selection of state using XML subtree filter from a server:

.. code-block:: python

  config = session.get(select="<devices><device><name>RouterA</name></device></devices>")

Config
------
To get the running config from a server:

.. code-block:: python

  config = session.get_config()

To get candidate config from a server:

.. code-block:: python

  config = session.get_config(source="candidate")

To get a specific selection of config using xpath from a server:

.. code-block:: python

  config = session.get_config(select="/devices/device[name='RouterA']")

To get a specific selection of config using XML subtree filter from a server:

.. code-block:: python

  config = session.get_config(select="<devices><device><name>RouterA</name></device></devices>")

To send and RPC to a server:

.. code-block:: python

  rpcout = session.send_rpc("<my-rpc/>")

Netconf Server
==============

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
