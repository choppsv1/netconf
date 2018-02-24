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
  $ netconf-client --host 127.0.0.1 --get-config
  <data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <sys:system xmlns:sys="urn:ietf:params:xml:ns:yang:ietf-system">
      <sys:hostname>tops</sys:hostname>
      <sys:clock>
        <sys:timezone-utc-offset>180</sys:timezone-utc-offset>
      </sys:clock>
    </sys:system>
  </data>

To request config filtered by an xpath expression.

.. code-block:: sh

  $ netconf-client --port 8300 -u admin -p admin --get-config="/system/clock"
  <data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <sys:system xmlns:sys="urn:ietf:params:xml:ns:yang:ietf-system">
      <sys:clock>
        <sys:timezone-utc-offset>180</sys:timezone-utc-offset>
      </sys:clock>
    </sys:system>
  </data>

Get State
=========

To request operational state (see :ref:`cli-auth` for authentication)

.. code-block:: sh

  $ netconf-client --host=127.0.0.1 --port=8300 --get
  <data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <sys:system-state xmlns:sys="urn:ietf:params:xml:ns:yang:ietf-system">
      <sys:system>
        <sys:os-name>Linux</sys:os-name>
        <sys:os-release>4.15.3-2-ARCH</sys:os-release>
        <sys:os-version>#1 SMP PREEMPT Thu Feb 15 00:13:49 UTC 2018</sys:os-version>
        <sys:machine>x86_64</sys:machine>
      </sys:system>
      <sys:clock>
        <sys:current-datetime>2018-02-24T12:57:18.537626</sys:current-datetime>
        <sys:boot-datetime>2018-02-23T09:12:22.838012</sys:boot-datetime>
      </sys:clock>
    </sys:system-state>
  </data>


To request state filtered by an xpath expression.

.. code-block:: sh

  $ netconf-client --port=8300 -u admin -p admin --get="/system-system/clock"
  <data xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <sys:system-state xmlns:sys="urn:ietf:params:xml:ns:yang:ietf-system">
      <sys:clock>
        <sys:current-datetime>2018-02-24T12:57:18.537626</sys:current-datetime>
        <sys:boot-datetime>2018-02-23T09:12:22.838012</sys:boot-datetime>
      </sys:clock>
    </sys:system-state>
  </data>