#!/usr/bin/env python
from setuptools import setup, find_packages

# Lets makes ure we have the correct modules installed before continuing.
# Had issues with people not having OpenSSL not installed, just
# wanted to run a check.
setup(
    name="CSR Generator",
        version="1.0",
        packages=find_packages(),
    install_requires=[ 'pyopenssl', 'argparse', 'pyyaml' ]
)
