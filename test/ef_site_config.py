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

class EFSiteConfig:
  """
  Installation-specific and global settings shared by all EF tools
  """

  # Region to work in when no region is otherwise specified (tools only support 1 region at present - this one)
  DEFAULT_REGION = "us-west-2"

  # Repo where tools and all EF data are
  EF_REPO = "github.com/fake"
  EF_REPO_BRANCH = "master"

  # Map environment::account alias (aliases must profiles in .aws/credentials for local use)
  ENV_ACCOUNT_MAP = {
    "test": "test",
    "dev": "dev",
    "staging": "staging",
    "prod": "prod"
  }

  # Map environment::number for environments that support multiple ephemeral replicas
  # Resolves as proto<0..N> up to number - 1 (proto0, proto1, proto2, proto3 for N = 4)
  # prod and account scoped envs are not allowed
  EPHEMERAL_ENVS = {
    "dev": 1,
    "staging": 1
  }

  # Bucket where late-bound service configs are found
  S3_CONFIG_BUCKET = "test"

  # Services in the service registry are clustered into groups, and can be addressed collectively by some tools.
  # The group "fixtures" is required and will be added to this list in later code; don't list it here.
  # The usual other groups are "platform_services" and "application_services".
  # Each group must be contained in an object in the service registry.
  SERVICE_GROUPS = {
    "application_services",
    "internal_services",
    "platform_services"
  }

  #### Version-management settings ####
  # What envs are allowed to have special versions?
  SPECIAL_VERSION_ENVS = ["staging"]
