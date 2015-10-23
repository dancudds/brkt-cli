# Copyright 2015 Bracket Computing, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# https://github.com/brkt/brkt-sdk-java/blob/master/LICENSE
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and
# limitations under the License.

import re
from setuptools import setup

version = ''
with open('brkt_cli/__init__.py', 'r') as fd:
    version = re.search(r'^VERSION\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

if not version:
    raise RuntimeError('Cannot find version information')

setup(
    name='brkt-cli',
    version=version,
    description='Bracket Computing command line interface',
    url='http://brkt.com',
    license='Apache 2.0',
    packages=['brkt_cli'],
    install_requires=['boto>=2.38.0', 'requests>=2.7.0'],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'brkt = brkt_cli:main',
        ]
    },
    package_dir={'brkt_cli': 'brkt_cli'},
    package_data={'brkt_cli': ['assets/ca_cert.pem']},
    test_suite='test'
)
