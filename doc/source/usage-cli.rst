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

  $ netconf-client … --hello
  urn:ietf:params:netconf:base:1.1
  urn:ietf:params:netconf:base:1.0
  urn:ietf:params:xml:ns:yang:ietf-system
  urn:ietf:params:netconf:capability:xpath:1.0

.. _cli-auth:

Authentication
==============

You can authenticate to the server using passwords, ssh keys, or your ssh agent. Below are some examples of all of these uses.

Password Authentication
-----------------------
.. code-block:: sh

  $ # Using a password
  $ netconf-client … --username=admin --password=admin

  $ # Using a password in an environment variable
  $ export PASS=admin
  $ netconf-client … --username=admin --password=env:PASS

  $ # Using a password in a file.
  $ echo "admin" > passfile
  $ netconf-client … --username=admin --password=file:passfile

SSH Authentication
------------------
.. code-block:: sh

  $ # Using a key from your SSH agent
  $ netconf-client …

  $ # Using a keyfile
  $ netconf-client … --keyfile=~/.ssh/id_rsa

  $ # Using a key from an environment variable (useful in CI environments)
  $ export MYKEY="$(cat ~/.ssh/id_rsa)"
  $ netconf-client … --keyfile=<(echo "$MYKEY") --hello

  $ # Using a keyfile with a passphrase from an environment variable
  $ export PASS="mypassphrase"
  $ netconf-client … --keyfile=~/.ssh/id_rsa --password=env:PASS

  $ # Using a keyfile with a passphrase from a file
  $ echo "mypassphrase" > passfile
  $ netconf-client … --keyfile=~/.ssh/id_rsa --password=file:passfile

Get Config
==========

To request config (see :ref:`cli-auth` for authentication).

.. code-block:: sh

  $ netconf-client … --get-config
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

  $ netconf-client … --get-config="/sys:system/sys:clock"
                     --namespaces="sys=urn:ietf:params:xml:ns:yang:ietf-system"
  <nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <sys:system xmlns:sys="urn:ietf:params:xml:ns:yang:ietf-system">
      <sys:clock>
        <sys:timezone-utc-offset>180</sys:timezone-utc-offset>
      </sys:clock>
    </sys:system>
  </nc:data>

Get State
=========

To request operational state (see :ref:`cli-auth` for authentication)

.. code-block:: sh

  $ netconf-client … --get
  <nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <sys:system xmlns:sys="urn:ietf:params:xml:ns:yang:ietf-system">
      <sys:hostname>tops</sys:hostname>
      <sys:clock>
        <sys:timezone-utc-offset>180</sys:timezone-utc-offset>
      </sys:clock>
    </sys:system>
    <sys:system-state xmlns:sys="urn:ietf:params:xml:ns:yang:ietf-system">
      <sys:platform>
        <sys:os-name>Linux</sys:os-name>
        <sys:os-release>5.4.14-arch1-1</sys:os-release>
        <sys:os-version>#1 SMP PREEMPT Thu, 23 Jan 2020 10:07:05 +0000</sys:os-version>
        <sys:machine>x86_64</sys:machine>
      </sys:platform>
      <sys:clock>
        <sys:current-datetime>2020-02-11T18:20:14.516992</sys:current-datetime>
        <sys:boot-datetime>2020-02-10T06:31:26.787100</sys:boot-datetime>
      </sys:clock>
    </sys:system-state>
  </nc:data>

To request state filtered by a sub-tree XML filter

.. code-block:: sh

  $ netconf-client --port=8300 -u admin -p admin --get '<system-state><platform/></system-state>'
  <nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <sys:system-state xmlns:sys="urn:ietf:params:xml:ns:yang:ietf-system">
      <sys:platform>
        <sys:os-name>Linux</sys:os-name>
        <sys:os-release>5.4.14-arch1-1</sys:os-release>
        <sys:os-version>#1 SMP PREEMPT Thu, 23 Jan 2020 10:07:05 +0000</sys:os-version>
        <sys:machine>x86_64</sys:machine>
      </sys:platform>
    </sys:system-state>
  </nc:data>

To request state filtered by an xpath expression.

.. code-block:: sh

  $ netconf-client … --get="/sys:system-state/sys:clock" \
                     --namespaces="sys=urn:ietf:params:xml:ns:yang:ietf-system"
  <nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <sys:system-state xmlns:sys="urn:ietf:params:xml:ns:yang:ietf-system">
      <sys:clock>
        <sys:current-datetime>2020-02-11T18:27:16.336916</sys:current-datetime>
        <sys:boot-datetime>2020-02-10T06:31:26.787025</sys:boot-datetime>
      </sys:clock>
    </sys:system-state>
  </nc:data>
