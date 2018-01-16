..
.. January 15 2018, Christian Hopps <chopps@gmail.com>
..

=====
Usage
=====

-----------------
Command Line Tool
-----------------

To request config from a server that has your key::

  $ netconf-client --host example.com <<EOF
      <get-config/>
  EOF

-----------
Development
-----------

To use netconf in a project::

  import netconf

To get config from a server::

  from netconf.client import NetconfSSHSession

  session = NetconfSSHSession(host, port, username, password)
  config = session.send_rpc("<get-config/>""
  session.close()
