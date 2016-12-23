# -*- coding: utf-8 -*-#
#
# October 1 2015, Christian Hopps <chopps@gmail.com>
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
import sys
import os
from setuptools import setup

required = [
    "lxml>=3.1.0",
    "paramiko>=1.10.1",
    "sshutil>=1.0.2",
]
if sys.platform == 'win32' and sys.version_info < (3, 5):
    required.append("backports.socketpair>=3.5.0.2")


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup (name='netconf',
       version='0.4.3',
       description='Netconf Client/Server Library',
       long_description=read("README.rst"),
       author='Christian E. Hopps',
       author_email='chopps@gmail.com',
       url='https://github.com/choppsv1/netconf',
       license='Apache License, Version 2.0',
       install_requires=required,
       packages=['netconf'])
