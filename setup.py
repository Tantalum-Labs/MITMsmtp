#!/usr/bin/env python3

import setuptools
import os

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="MITMsmtp",
    version="0.0.3-dev",
    author="Robin Meis",
    author_email="blog@smartnoob.de",
    description="An evil SMTP Server for client pentesting",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RobinMeis/MITMsmtp",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    extras_require={
        # NTLM relay mode delegates to impacket's ntlmrelayx. Install with:
        #   pip install MITMsmtp[relay]
        "relay": ["impacket>=0.11.0"],
    },
    entry_points={
        'console_scripts': [
            'MITMsmtp = MITMsmtp.__main__:main'
        ]
    },
    include_package_data=True,
)
