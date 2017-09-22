# noinspection PyClassHasNoInit

"""
Copyright 2016-2017 Ellation, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from ef_site_config import EFSiteConfig


class EFConfig(EFSiteConfig):
  """
  Installation-specific and global settings shared by all EF tools
  Don't change anything here.
  All supported site-specific customizations are found in ef_site_config.py
  """

  # Default service registry file name
  DEFAULT_SERVICE_REGISTRY_FILE = "service_registry.json"
  PARAMETER_FILE_SUFFIX = ".parameters.json"
  POLICY_TEMPLATE_PATH_SUFFIX = "/policy_templates/"
  # the service group 'fixtures' always exists
  EFSiteConfig.SERVICE_GROUPS.add("fixtures")

  # Convenient list of all mapped accounts
  ACCOUNT_ALIAS_LIST = set(EFSiteConfig.ENV_ACCOUNT_MAP.values())

  # These environments are for account-wide resources; they have a ".<ACCOUNT_ALIAS>" suffix
  ACCOUNT_SCOPED_ENVS = ["global", "mgmt"]

  # Protected environments are unique and non-ephemeral
  PROTECTED_ENVS = ["prod"] + ACCOUNT_SCOPED_ENVS

  # Convenient list of all possible valid environments
  ENV_LIST = []
  VALID_ENV_REGEX = ""
  for env in EFSiteConfig.ENV_ACCOUNT_MAP.keys():
    if env not in PROTECTED_ENVS and env in EFSiteConfig.EPHEMERAL_ENVS:
      ENV_LIST.extend((lambda env=env: [env + str(x) for x in range(EFSiteConfig.EPHEMERAL_ENVS[env])])())
      VALID_ENV_REGEX += "{}[0-{}]|".format(env, EFSiteConfig.EPHEMERAL_ENVS[env] - 1)
    else:
      ENV_LIST.append(env)
      VALID_ENV_REGEX += "{}|".format(env)

  ENV_LIST.extend("global." + x for x in ACCOUNT_ALIAS_LIST)
  ENV_LIST.extend("mgmt." + x for x in ACCOUNT_ALIAS_LIST)
  ENV_LIST = sorted(ENV_LIST)
  VALID_ENV_REGEX += "global|mgmt"

  ## Version system
  # suffix used for naming deployable service AMIs
  AMI_SUFFIX = "-release"
  # content-encoding for S3 version registry
  S3_VERSION_CONTENT_ENCODING = "utf-8"
  # Metdata key on a version object to indicate who modified it
  S3_VERSION_BUILDNUMBER_KEY = "ef-buildnumber"
  # Metdata key on a version object to indicate who modified it
  S3_VERSION_COMMITHASH_KEY = "ef-commithash"
  # Metdata key on a version object to indicate who modified it
  S3_VERSION_LOCATION_KEY = "ef-location"
  # Metdata key on a version object to indicate who modified it
  S3_VERSION_MODIFIEDBY_KEY = "ef-modifiedby"
  # Metadata key on a version object to indicate its status
  S3_VERSION_STATUS_KEY = "ef-version-status"
  # Metadata version status values
  S3_VERSION_STATUS_STABLE = "stable"
  S3_VERSION_STATUS_UNDEFINED = "undefined"
  VERSION_KEYS = {
    "ami-id": {
      "allow_latest": True,
      "allowed_types": ["aws_ec2", "http_service"]
    },
    "config": {},
    "dist-hash": {
      "allowed_types": ["dist_static"]
    }
  }
  # Some envs' version entries can be set via these special values, meaning 'use the value found there'
  SPECIAL_VERSIONS = ["=latest", "=prod", "=staging"]
