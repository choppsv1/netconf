..
.. January 15 2018, Christian Hopps <chopps@gmail.com>
..

netconf
=======

This package supports creating both netconf clients and servers. Additionally a
CLI netconf client is included. The following modules are present:

- ``base`` - Shared netconf support classes.
- ``error`` - Netconf error classes.
- ``client`` - Netconf client classes.
- ``server`` - Netconf server classes.
- ``util`` - Netconf utility functions.

`netconf` uses `_sshutil` and thus supports your SSH agent and SSH config when
using the client.

Contents:

.. toctree::
   :maxdepth: 2

   installation
   usage
   reference

.. _sshutil: https://github.com/choppsv1/pysshutil
