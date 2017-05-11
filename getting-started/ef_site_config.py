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

class EFSiteConfig:
  """
  Installation-specific settings shared by all EF tools
  """

  # Region to work in when no region is otherwise specified (tools only support 1 region at present - this one)
  #   Example: DEFAULT_REGION = "us-east-1"
  DEFAULT_REGION = ""

  # Repo where tools and all EF data are
  #   Example: EF_REPO = "github.com/account/repo"
  EF_REPO = ""

  # Branch in EF_REPO to deploy CloudFormation templates from; probably "master"
  #   Example: EF_REPO_BRANCH = "master"
  EF_REPO_BRANCH = ""

  # Map environment::account alias (aliases must have matching profiles in .aws/credentials)
  #   Example, assuming there are 3 AWS account altogether
  #   "internal": "mycompanyint",
  #   "prod": "mycompany",
  #   "proto": "mycompanynonprod",
  #   "staging": "mycompanynonprod"
  ENV_ACCOUNT_MAP = {
    "internal": "",
    "prod": "",
    "proto": "",
    "staging": ""
  }

  # Number of prototype environments, numbered 0..N-1 (4 or fewer recommended)
  #   Example: PROTO_ENVS = 4
  PROTO_ENVS = 4

  # Bucket where late-bound service configs are found. See doc/name-patterns.md for S3 bucket naming conventions
  #   Bucket name should be in this form: <S3PREFIX>-global-configs
  #   Bucket does not have to exist yet (you will need the built tools to create it via CloudFormation)
  #   Example: S3_CONFIG_BUCKET = "mycompany-myproject-global-configs
  S3_CONFIG_BUCKET = ""

  # Services in the service registry are clustered into groups, and can be addressed collectively by some tools
  #   The group "fixtures" is required and will be added by code; don't list it here
  #   The usual other groups are "platform_services", "internal_services", and "application_services"
  #   Each group must be contained in an object in the service registry.
  SERVICE_GROUPS = {
    "application_services",
    "internal_services",
    "platform_services"
  }

  ## Version-management settings ##
  #   is --noprecheck allowed with ef-version --set and --rollback?
  ALLOW_EF_VERSION_SKIP_PRECHECK = True

  # Bucket where versions are found
  #   Bucket name should be in this form: <S3PREFIX>-global-versions
  #   Bucket does not have to exist yet (you will need the built tools to create it via CloudFormation)
  #   Example: S3_VERSION_BUCKET = "mycompany-myproject-global-versions
  S3_VERSION_BUCKET = ""

  # What envs are allowed to have special versions?
  #   Usually this only applies to 'proto'
  #   Example: SPECIAL_VERSION_ENVS = ["proto"]
  SPECIAL_VERSION_ENVS = ["proto"]
