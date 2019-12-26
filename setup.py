#!/usr/bin/env python

from setuptools import setup

import versioneer


def readme():
    with open('README.md') as f:
        return f.read()


setup(
    name='ef-open',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    packages=[
        'efopen'
    ],
    install_requires=[
        'boto3',
        'click',
        'PyYAML',
        'cfn-lint',
        'requests',
        'yamllint'
    ],
    extras_require={
        'test': [
            'mock',
            'pylint',
        ]
    },
    entry_points={
        'console_scripts': [
            'ef-cf=efopen.ef_cf:main',
            'ef-cf-diff=efopen.ef_cf_diff:main',
            'ef-check-config=efopen.ef_check_config:main',
            'ef-generate=efopen.ef_generate:main',
            'ef-instanceinit=efopen.ef_instanceinit:main',
            'ef-password=efopen.ef_password:main',
            'ef-resolve-config=efopen.ef_resolve_config:main',
            'ef-version=efopen.ef_version:main'
        ],
    },
    url='https://github.com/crunchyroll/ef-open',
    license="Apache License 2.0",
    author='Ellation, Inc.',
    author_email='ops@ellation.com',
    description='CloudFormation Tools by Ellation',
    long_description=readme(),
    long_description_content_type='text/markdown'
)
