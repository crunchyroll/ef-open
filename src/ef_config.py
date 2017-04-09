# noinspection PyClassHasNoInit

"""
Copyright 2016 Ellation, Inc.

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
  LOCAL_VM_LABEL = "localvm"
  PARAMETER_FILE_SUFFIX = ".parameters.json"
  POLICY_TEMPLATE_PATH_SUFFIX = "/policy_templates/"
  # the service group 'fixtures' always exists
  SERVICE_GROUPS.add("fixtures")
  VALID_ENV_REGEX = "prod|staging|proto[0-{}]|global|mgmt|internal".format(PROTO_ENVS - 1)

  # Convenient list of all mapped accounts
  ACCOUNT_ALIAS_LIST = set(ENV_ACCOUNT_MAP.values())

  # Convenient list of all possible valid environments
  ENV_LIST = ["prod", "staging", "internal"]
  ENV_LIST.extend("global." + x for x in ACCOUNT_ALIAS_LIST)
  ENV_LIST.extend("mgmt." + x for x in ACCOUNT_ALIAS_LIST)
  ENV_LIST.extend("proto" + str(x) for x in range(PROTO_ENVS))
  ENV_LIST = sorted(ENV_LIST)

  # These environments are for account-wide resources; they have a ".<ACCOUNT_ALIAS>" suffix
  ACCOUNT_SCOPED_ENVS = ["global", "mgmt"]

  ## Version system
  # content-encoding for S3 version registry
  S3_VERSION_CONTENT_ENCODING = "utf-8"
  # Metdata key on a version object to indicate who modified it
  S3_VERSION_MODIFIEDBY_KEY = "ef-modifiedby"
  # Metadata key on a version object to indicate its status
  S3_VERSION_STATUS_KEY = "ef-version-status"
  # Metadata version status values
  S3_VERSION_STATUS_STABLE = "stable"
  S3_VERSION_STATUS_UNDEFINED = "undefined"
  # What values other than a literal version are allowed for each environment?
  # Some envs' version entries can be set to these special values, meaning 'use the value found there'
  SPECIAL_VERSIONS = ["=latest", "=prod", "=staging"]
