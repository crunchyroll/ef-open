[![crunchyroll](https://circleci.com/gh/crunchyroll/ef-open.svg?style=svg)](https://circleci.com/gh/crunchyroll/ef-open)

# ef_open
EllationFormation: CloudFormation Tools for AWS by Ellation

# Installation
The easiest way to install ef-open is to use pip in a virtualenv:

    $ pip install ef-open

or, if you are not installing in a virtualenv, to install globally:

    $ sudo pip install ef-open

or for your user:

    $ pip install --user ef-open

If you have the ef-open installed and want to upgrade to the latest version you can run:

    $ pip install --upgrade ef-open

# Python version
You may need to use python3 on your local system this may map to:
    $ pip3 install ef-open

# Use
`ef-cf` - Evaluate templatized CloudFormation templates, with the option to generate changesets or apply them
`ef-cf-diff` - Test some or all templates against a target environment, for differences
`ef-check-config` - Validate the config files for JSON correctness
`ef-generate` - Ensure the existence of various standard elements for a target environment
`ef-instanceinit` - Host startup script which copies customized instance config from S3 to the local host
`ef-password` - Manage an encrypted secrets file, with the keys stored in AWS's KMS
`ef-resolve-config` - Generate late-bind config assets, for testing
`ef-version` - Manage versioned tagging for AMI's and static assets

# Development
## Testing and Linting
This project uses Python `unittest` framework for unit tests, and `pylint` for lint checking.
```
python setup.py test

pylint --rcfile=./pylintrc ./efopen
```

## Versions
This project uses [Versioneer](https://github.com/warner/python-versioneer) to manage the release versions, based on Git tags on the code repository.

Versions for Git working copies are generated on the fly based on the commit status of the working copy, and will change automatically as modifications are made and committed to the repository.  For released packages, versions are frozen during packaging, and reflect the state of the working copy at the time the package was built.

Generated package versions follow the PEP440 spec, and will be of the form:
```
TAG[+DISTANCE.gSHORTHASH[.dirty]]
```
Where:
`TAG` - the most recent Git tag string (written by the user when the Git tag was created)
`DISTANCE` - the number of commits between the current commit and the given TAG.  If this git commit _is_ the tagged commit, this value will be omitted.
`SHORTHASH` - the short Git ref hash, specifying the specific Git ref of the current commit.  If this git commit _is_ the tagged commit, this value will be omitted.
".dirty" - will be appended if the working copy has uncommitted changes to tracked files (but importantly, un-tracked files will not affect this flag).

### Creating a new Release
To cut a new package release (for example, for a version `1.2.3`):
- Git tag the target Git commit:
``` bash
git tag -a 1.2.3 -m "Some reasonable tag message"
```
- Push the code and tag:
``` bash
git push && git push --tags
```

The Jenkins CI pipeline will then recognize the new tag, build it, and publish it to PyPI.  To be sure, watch the Jenkins pipeline progress and ensure that the new package tag is published to PyPI.

_DO NOT_ delete a tag and retag the same tag on a different commit.  This will not result in a replacement in PyPI, it will just make you sad.

# License
Copyright 2016-2017 Ellation, Inc.
Licensed under the Apache 2.0 License
