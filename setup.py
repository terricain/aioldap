#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    'ldap3==2.5',
]

setup(
    name='aioldap',
    version='0.4.2',
    description="Async ldap library sorta based off ldap3",
    long_description=readme + '\n\n' + history,
    author="Terry Cain",
    author_email='terry@terrys-home.co.uk',
    url='https://github.com/terrycain/aioldap',
    packages=find_packages(include=['aioldap*']),
    include_package_data=True,
    install_requires=requirements,
    license="Apache 2",
    zip_safe=False,
    keywords='aioldap',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    test_suite='tests'
)
