#! /usr/bin/env python

from pip.req import parse_requirements
from setuptools import setup, find_packages
import os
import sys

deps = [
    'six',
]

if sys.version_info[:2] == (2, 7):
    deps.extend([
        'poster',
    ])

if sys.version_info >= (3, 5):
    """If running on py3, you need to `pip install -r requirements-py3.txt` after
    running setup.py, until the dependencies either support py3 or we drop their
    use."""
    pass

setup(
    name="signtool",
    version="1.0.8",
    description="Mozilla Signing Tool",
    author="Release Engineers",
    author_email="release+python@mozilla.com",
    packages=find_packages(exclude="tests"),
    test_suite='tests',
    zip_safe=False,
    license="MPL 2.0",
    install_requires=deps,
    entry_points={
        'console_scripts': [
            'signtool = signtool.signtool:main'
        ],
    },
    # include files listed in MANIFEST.in
    include_package_data=True,
    package_data={ "": ["requirements-py3.txt"]},
    classifiers=(
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5",
    ),
)
