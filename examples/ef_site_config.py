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
  DEFAULT_REGION = ""  # your region, like us-west-2

  # Repo where tools and all EF data are
  EF_REPO = "" # your repo, like "github.com/account/repo"
  EF_REPO_BRANCH = "master" # your branch, we recommend master

  # Map environment::account alias (aliases must have matching profiles in .aws/credentials)
  ENV_ACCOUNT_MAP = {
    "internal": "", # The alias for the account of each environment.
    "prod": "",
    "proto": "",
    "staging": ""
  }

  # Number of prototype environments, numbered 0..N-1
  PROTO_ENVS = 4 # we use 4

  # Bucket where late-bound service configs are found
  S3_CONFIG_BUCKET = "" #name-of-config-bucket

  # Services in the service registry are clustered into groups, and can be addressed collectively by some tools.
  # The group "fixtures" is required and will be added to this list in later code; don't list it here.
  # The usual other groups are "platform_services" and "application_services".
  # Each group must be contained in an object in the service registry.
  SERVICE_GROUPS = {
    "application_services", # These are ours.
    "internal_services",
    "platform_services"
  }

  #### Version-management settings ####
  # is --noprecheck allowed with ef-version --set and --rollback?
  ALLOW_EF_VERSION_SKIP_PRECHECK = True
  # Bucket where versions are found
  S3_VERSION_BUCKET = "" # name of your bucket that holds versions
  # What envs are allowed to have special versions?
  SPECIAL_VERSION_ENVS = ["proto"] # usually this is just 'proto'
