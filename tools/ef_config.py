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

class EFConfig:
  """
  Installation-specific and global settings shared by all EF tools
  """

  #### CUSTOMIZABLE PARAMS ####

  # Region to work in when no region is otherwise specified (tools only support 1 region at present - this one)
  DEFAULT_REGION = "##YOUR_DEFAULT_REGION##"

  # Default service registry file name
  DEFAULT_SERVICE_REGISTRY_FILE = "service_registry.json"

  # Repo where tools and all EF data are
  EF_REPO = "github.com/##YOUR_ACCOUNT##/##YOUR_REPO##"
  EF_REPO_BRANCH = "master"

  # Map environment::account alias (aliases must profiles in .aws/credentials for local use)
  ENV_ACCOUNT_MAP = {
    "prod": "##YOUR_PROD_ACCOUNT_ALIAS##",
    "proto": "##YOUR_PROTO_ACCOUNT_ALIAS##",
    "staging": "##YOUR_STAGING_ACCOUNT_ALIAS##"
  }

  # Number of prototype environments, numbered 0..N-1
  PROTO_ENVS = 4

  # Bucket where late-bound service configs are found
  S3_CONFIG_BUCKET = "##YOUR-S3-PREFIX##-global-configs"

  # Services in the service registry are clustered into groups, and can be addressed collectively by some tools.
  # The group "fixtures" is required and will be added to this list in later code; don't list it here.
  # The usual other groups are "platform_services" and "application_services".
  # Each group must be contained in an object in the service registry.
  SERVICE_GROUPS = {
    "application_services",
    "platform_services"
  }


  #### DO NOT CUSTOMIZE BELOW THIS LINE ####

  #### Constants ####
  LOCAL_VM_LABEL = "localvm"
  PARAMETER_FILE_SUFFIX = ".parameters.json"
  POLICY_TEMPLATE_PATH_SUFFIX = "/policy_templates/"
  # the service group 'fixtures' always exists
  SERVICE_GROUPS.add("fixtures")
  VALID_ENV_REGEX = "prod|staging|proto[0-{}]|global|mgmt".format(PROTO_ENVS - 1)

  # Convenient list of all mapped accounts
  ACCOUNT_ALIAS_LIST = set(ENV_ACCOUNT_MAP.values())

  # Convenient list of all possible valid environments
  ENV_LIST = ["prod", "staging"]
  ENV_LIST.extend(map(lambda x: "global." + x, ACCOUNT_ALIAS_LIST))
  ENV_LIST.extend(map(lambda x: "mgmt." + x, ACCOUNT_ALIAS_LIST))
  ENV_LIST.extend(map(lambda x: "proto" + str(x), range(PROTO_ENVS)))
  ENV_LIST = sorted(ENV_LIST)

  # These environments are for account-wide resources; they have a ".<ACCOUNT_ALIAS>" suffix
  ACCOUNT_SCOPED_ENVS = ["global", "mgmt"]
