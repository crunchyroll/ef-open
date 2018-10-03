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

from collections import Counter
import json
from os.path import isfile, normpath
import subprocess

from ef_config import EFConfig

class EFServiceRegistry(object):
  """
  Wraps interactions with the Service Registry
  Tries to find service registry in repo if service_registry_file is omitted in constructor

  Args:
    service_registry_file - /path/to/service_registry; default: EF_Config.DEFAULT_SERVICE_REGISTRY_FILE in repo root
  """

  def __init__(self, service_registry_file=None):
    """
    Args:
      service_registry_file: the file containing the service registry
    Raises:
      IOError: if file can't be found or can't be opened
      RuntimeError: if repo or branch isn't as spec'd in ef_config.EF_REPO and ef_config.EF_REPO_BRANCH
      CalledProcessError: if 'git rev-parse' command to find repo root could not be run
    """
    # If a file wasn't provided, try to fetch the default
    if service_registry_file is None:
      repo_root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).rstrip()
      self._service_registry_file = normpath("{}/{}".format(repo_root, EFConfig.DEFAULT_SERVICE_REGISTRY_FILE))
    else:
      self._service_registry_file = service_registry_file
    if not isfile(self._service_registry_file):
      raise IOError("Not a file: {}".format(self._service_registry_file))
    # Read the service registry
    service_registry_fh = open(self._service_registry_file, "r")
    try:
      self.service_registry_json = json.load(service_registry_fh)
    except ValueError:
      raise Exception("Malformed service registry file")
    # Validate service registry
    # 1. All service groups listed in EFConfig.SERVICE_GROUPS must be present
    for service_group in EFConfig.SERVICE_GROUPS:
      if not self.service_registry_json.has_key(service_group):
        raise RuntimeError("service registry: {} doesn't have '{}' service group listed in EFConfig".format(
                           self._service_registry_file, service_group))
    # 2. A service name must be unique and can only belong to one group
    service_counts = Counter()
    for service_group in EFConfig.SERVICE_GROUPS:
      service_counts.update(self.services(service_group).keys())
    for service_group in service_counts:
      if service_counts.get(service_group) > 1:
        raise RuntimeError("service name appears more than once in service registry: {}".format(service_group))

  @property
  def filespec(self):
    """
    Returns:
      path/to/service_registry_file
    """
    return self._service_registry_file

  def services(self, service_group=None):
    """
    Args:
      service_group: optional name of service group
    Returns:
      if service_group is omitted or None, flattened dict of all service records in the service registry
      if service_group is present, dict of service records in that group
    """
    # Specific service group requested
    if service_group is not None:
      if service_group not in EFConfig.SERVICE_GROUPS:
        raise RuntimeError("service registry: {} doesn't have '{}' section listed in EFConfig".format(
          self._service_registry_file, service_group))
      else:
        return self.service_registry_json[service_group]
    # Specific service group not requested - flatten and return all service records
    else:
      result = dict()
      for service_group in EFConfig.SERVICE_GROUPS:
        result.update(self.service_registry_json[service_group])
      return result

  def iter_services(self, service_group=None):
    """
    Args:
      service_group: optional name of service group
    Returns:
      if service_group is omitted or None, an Iterator over all flattened service records in the service registry
      if service_group is present, an Iterator over all service records in that group
    """
    if service_group is not None:
      if service_group not in EFConfig.SERVICE_GROUPS:
        raise RuntimeError("service registry: {} doesn't have '{}' section listed in EFConfig".format(
          self._service_registry_file, service_group))
      return self.service_registry_json[service_group].iteritems()
    else:
     return self.services().iteritems()

  def valid_envs(self, service_name):
    """
    Args:
      service_name: the name of the service in the service registry
    Returns:
      a list of strings - all the valid environments for 'service'
    Raises:
      RuntimeError if the service wasn't found
    """
    service_record = self.service_record(service_name)
    if service_record is None:
      raise RuntimeError("service registry doesn't have service: {}".format(service_name))

    # Return empty list if service has no "environments" section
    if not (service_record.has_key("environments")):
      return []
    # Otherwise gather up the envs
    service_record_envs = service_record["environments"]
    result = []
    for service_env in service_record_envs:
      if service_env not in EFConfig.PROTECTED_ENVS and service_env in EFConfig.EPHEMERAL_ENVS:
        result.extend((lambda env=service_env: [env + str(x) for x in range(EFConfig.EPHEMERAL_ENVS[env])])())
      else:
        result.append(service_env)
    return result

  def service_record(self, service_name):
    """
    Args:
      service_name: the name of the service in the service registry
    Returns:
      the entire service record from the service registry or None if the record was not found
    """
    if not self.services().has_key(service_name):
      return None
    return self.services()[service_name]

  def service_group(self, service_name):
    """
    Args:
      service_name: the name of the service in the service registry
    Returns:
      the name of the group the service is in, or None of the service was not found
    """
    for group in EFConfig.SERVICE_GROUPS:
      if self.services(group).has_key(service_name):
        return group
    return None

  def service_region(self, service_name):
    """
    Args:
      service_name: the name of the service in the service registry
    Returns:
      the region the service is in, or EFConfig.DEFAULT_REGION if the region was not found
    """
    if not self.services()[service_name].has_key("region"):
      return EFConfig.DEFAULT_REGION
    else:
      return self.services()[service_name]["region"]

  def version_keys(self):
    return self.service_registry_json["version_keys"]

  def allows_latest(self, version_key_name):
    """
    Does this version key allow 'latest' as an option (e.g. "latest AMI" makes sense and is allowed)
    Args:
      version_key_name: the version key to check for "allow_latest"
    Returns:
      True if the version key allows latest, False if it does not
    Raises:
      ValueError if the key was not found
    """
    if not self.version_keys().has_key(version_key_name):
      raise RuntimeError("service registry doesn't have a version key entry for: {}".format(version_key_name))
    if not self.version_keys()[version_key_name].has_key("allow_latest"):
      raise RuntimeError("service registry key {} doesn't have an 'allow_latest' value".format(
        version_key_name))
    return self.version_keys()[version_key_name]["allow_latest"]
