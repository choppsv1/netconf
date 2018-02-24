..
.. January 15 2018, Christian Hopps <chopps@gmail.com>
..

**********
CLI Client
**********

Hello - Get Capabilities
========================

To get the capabilities of a server:

.. code-block:: sh

  $ netconf-client --host example.com --hello

.. _cli-auth:

Authentication
==============

You can authenticate to the server using passwords, ssh keys, or your ssh agent. Below are some examples of all of these uses.

Password Authentication
-----------------------
.. code-block:: sh

   $ # Using a password
   $ netconf-client --host example.com --username=admin --password=admin --get-config

   $ # Using a password in an environment variable
   $ export PASS=admin
   $ netconf-client --host example.com --username=admin --password=env:PASS --get-config

   $ # Using a password in a file.
   $ echo "admin" > passfile
   $ netconf-client --host example.com --username=admin --password=file:passfile --get-config

SSH Authentication
------------------
.. code-block:: sh

   $ # Using a key from your SSH agent
   $ netconf-client --host example.com --get-config

   $ # Using a keyfile
   $ netconf-client --host example.com --get-config --keyfile=~/.ssh/id_rsa

   $ # Using a key from an environment variable (useful in CI environments)
   $ export MYKEY="$(cat ~/.ssh/id_rsa)"
   $ netconf-client --host example.com --get-config --keyfile=<(echo "$MYKEY")

   $ # Using a keyfile with a passphrase from an environment variable
   $ export PASS="mypassphrase"
   $ netconf-client --host example.com --get-config --keyfile=~/.ssh/id_rsa --password=env:PASS

   $ # Using a keyfile with a passphrase from a file
   $ echo "mypassphrase" > passfile
   $ netconf-client --host example.com --get-config --keyfile=~/.ssh/id_rsa --password=file:passfile

Get Config
==========

To request config using SSH.

.. code-block:: sh

   $ # Using a key from your SSH agent
   $ netconf-client --host example.com --get-config

Get State
=========
To request operational state (see :ref:`cli-auth` for authentication)

.. code-block:: sh

  $ netconf-client --host --get


Filtering
=========
You can specify xpath or subtree filtering to the get commands.

.. code-block:: sh

  $ netconf-client --host --get-config
