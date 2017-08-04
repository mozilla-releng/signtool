#! /usr/bin/env python

from setuptools import setup, find_packages

deps = [
    'requests',
    'six',
]

setup(
    name="signtool",
    version="3.1.4",
    description="Mozilla Signing Tool",
    author="Release Engineers",
    author_email="release+python@mozilla.com",
    url="https://github.com/mozilla-releng/signtool",
    packages=find_packages(),
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
    classifiers=(
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5",
    ),
)
