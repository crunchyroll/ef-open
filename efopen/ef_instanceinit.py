"""
Instance initialization
This is installed on EC2 instances and local dev to load configuration values at startup.
Lambda initialization is not available yet.

For config object paths in AWS, see:
https://ellation.atlassian.net/wiki/display/DEVOPS/VRV+Name+Patterns+and+Paths


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
from __future__ import print_function
from grp import getgrnam
from syslog import closelog, openlog, syslog
from os import chmod, chown, makedirs
from os.path import dirname, normpath
from pwd import getpwnam
from socket import gethostname
import sys

import boto3
import boto3.utils
import botocore.exceptions

from ef_config import EFConfig
from ef_instanceinit_config_reader import EFInstanceinitConfigReader
from ef_utils import http_get_instance_role, http_get_metadata, whereami
from ef_conf_utils import get_account_alias
from ef_template_resolver import EFTemplateResolver

# constants
LOG_IDENT = "ef-instanceinit"
VIRTUALBOX_CONFIG_ROOT = "/vagrant/configs"

# globals
RESOURCES = {}  # boto resources (easier to use for some things)
WHERE = None


def log_info(message):
  """
  Log a message to log_info and console, and return
  Args:
    message:
  """
  print(message)
  syslog(message)


def critical(message):
  """
  Log critical error to log_info and console and exit with error status
  """
  log_info(message)
  closelog()
  sys.exit(1)


def get_user_group(dest):
  """
  Given a dictionary object representing the dest JSON in the late bind config's parameter file, return two
  values, the user and group
  Args:
      dest: dict object from the late bind config's parameters file e.g. dest["user_group"] = "Bob:devops"

  Returns:
      user: user that the late bind config belongs to
      group: group that the late bind config belongs to

  """
  return dest["user_group"].split(":")


def merge_files(service, skip_on_user_group_error=False):
  """
  Given a prefix, find all templates below; merge with parameters; write to "dest"
  Args:
    service: "<service>", "all", or "ssh"
    skip_on_user_group_error: True or False

  For S3, full path becomes:
    s3://ellation-cx-global-configs/<service>/templates/<filename>
    s3://ellation-cx-global-configs/<service>/parameters/<filename>.parameters.<yaml|yml|json>
  For filesystem, full path becomes:
    /vagrant/configs/<service>/templates/<filename>
    /vagrant/configs/<service>/parameters/<filename>.parameters.<yaml|yml|json>
  """
  if WHERE == "ec2":
    config_reader = EFInstanceinitConfigReader("s3", service, log_info, RESOURCES["s3"])
    resolver = EFTemplateResolver()
  elif WHERE == "virtualbox-kvm":
    config_path = "{}/{}".format(VIRTUALBOX_CONFIG_ROOT, service)
    config_reader = EFInstanceinitConfigReader("file", config_path, log_info)
    environment = EFConfig.VAGRANT_ENV
    resolver = EFTemplateResolver(env=environment, profile=get_account_alias(environment),
                                  region=EFConfig.DEFAULT_REGION, service=service)

  while config_reader.next():
    log_info("checking: {}".format(config_reader.current_key))

    # if 'dest' for the current object contains an 'environments' list, check it
    dest = config_reader.dest
    if "environments" in dest:
      if not resolver.resolved["ENV_SHORT"] in dest["environments"]:
        log_info("Environment: {} not enabled for {}".format(
          resolver.resolved["ENV_SHORT"], config_reader.current_key)
        )
        continue

    # If 'dest' for the current object contains a user_group that hasn't been created in the environment yet and the
    # flag is set to True to skip, log the error and move onto the next config file without blowing up.
    if skip_on_user_group_error:
      user, group = get_user_group(dest)
      try:
        getpwnam(user).pw_uid
      except KeyError:
        log_info("File specifies user {} that doesn't exist in environment. Skipping config file.".format(user))
        continue
      try:
        getgrnam(group).gr_gid
      except KeyError:
        log_info("File specifies group {} that doesn't exist in environment. Skipping config file.".format(group))
        continue

    # Process the template_body - apply context + parameters
    log_info("Resolving template")
    resolver.load(config_reader.template, config_reader.parameters)
    rendered_body = resolver.render()
    if not resolver.resolved_ok():
      critical("Couldn't resolve all symbols; template has leftover {{ or }}: {}".format(resolver.unresolved_symbols()))

    # Write the rendered file
    dir_path = normpath(dirname(dest["path"]))
    # Resolved OK. try to write the template
    log_info("make directories: {} {}".format(dir_path, dest["dir_perm"]))
    try:
      makedirs(dir_path, int(dest["dir_perm"], 8))
    except OSError as error:
      if error.errno != 17:
        critical("Error making directories {}".format(repr(error)))
    log_info("open: " + dest["path"] + ",w+")
    try:
      outfile = open(dest["path"], 'w+')
      log_info("write")
      outfile.write(rendered_body)
      log_info("close")
      outfile.close()
      log_info("chmod file to: " + dest["file_perm"])
      chmod(dest["path"], int(dest["file_perm"], 8))
      user, group = get_user_group(dest)
      uid = getpwnam(user).pw_uid
      gid = getgrnam(group).gr_gid
      log_info("chown last directory in path to: " + dest["user_group"])
      chown(dir_path, uid, gid)
      log_info("chown file to: " + dest["user_group"])
      chown(dest["path"], uid, gid)
    except Exception as error:
      critical("Error writing file: " + dest["path"] + ": " + repr(error))


def main():
  global RESOURCES, WHERE

  openlog(LOG_IDENT)

  WHERE = whereami()
  if WHERE == "unknown":
    critical("Cannot determine whether operating context is ec2 or local. Exiting.")
  elif WHERE == "local":
    critical("local mode not supported: must run under virtualbox-kvm or in ec2")
  elif WHERE == 'jenkins':
    critical("will not run inside a Jenkins environment")
  elif WHERE == "ec2":
    # get info needed for logging
    try:
      instance_id = http_get_metadata('instance-id')
      log_info("Instance id: " + instance_id)
    except IOError as error:
      critical("Error retrieving instance-id metadata: " + repr(error))

  log_info("startup")
  log_info("boto3: " + str(boto3.utils.sys.version_info))
  log_info("boto3: " + str(boto3.utils.sys.version))
  # Tailor to operating mode
  if WHERE == "virtualbox-kvm":
    service = gethostname().split(".", 1)[0]
  elif WHERE == "ec2":
    log_info("EC2: setting up S3 client")
    try:
      session = boto3.Session()
      # S3 iteration is easier using the S3 Resource
      RESOURCES["s3"] = session.resource("s3")
    except (botocore.exceptions.BotoCoreError, IOError) as e:
      critical("Error setting up S3 resource " + repr(e))
    service = http_get_instance_role()

  log_info("platform: {} service: {}".format(WHERE, service))

  merge_files("all")
  merge_files("ssh", skip_on_user_group_error=True)
  merge_files(service)

  log_info("exit: success")
  closelog()


if __name__ == "__main__":
  main()
