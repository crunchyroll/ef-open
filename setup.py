#!/usr/bin/env python

from setuptools import setup

import versioneer


def readme():
    with open('README.md') as f:
        return f.read()


setup(
    name='crf-open',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    packages=[
        'crfopen'
    ],
    install_requires=[
        'boto3>=1.17.112',
        'click<=7.1.2',
        'PyYAML<=5.4.1',
        'cfn-lint',
        'requests<=2.25.1',
        'tenacity==7.0.0',
        'yamllint<=1.25.0'
    ],
    extras_require={
        'test': [
            'mock',
            'pylint',
        ]
    },
    entry_points={
        'console_scripts': [
            'crf-cf=crfopen.crf_cf:main',
            'crf-cf-diff=crfopen.crf_cf_diff:main',
            'crf-check-config=crfopen.crf_check_config:main',
            'crf-generate=crfopen.crf_generate:main',
            'crf-instanceinit=crfopen.crf_instanceinit:main',
            'crf-password=crfopen.crf_password:main',
            'crf-resolve-config=crfopen.crf_resolve_config:main',
            'crf-version=crfopen.crf_version:main'
        ],
    },
    url='https://github.com/crunchyroll/crf-open',
    license="Apache License 2.0",
    author='Crunchyroll, Inc.',
    author_email='ops@crunchyroll.com',
    description='CloudFormation Tools by Crunchyroll',
    long_description=readme(),
    long_description_content_type='text/markdown'
)
