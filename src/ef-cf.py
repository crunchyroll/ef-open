#!/usr/bin/env python

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

from __future__ import print_function
import argparse
import json
from os import getenv
from os.path import basename, dirname, isfile, splitext
import sys

import botocore.exceptions

from ef_config import EFConfig
from ef_context import EFContext
from ef_service_registry import EFServiceRegistry
from ef_template_resolver import EFTemplateResolver
from ef_utils import create_aws_clients, fail, pull_repo

class EFCFContext(EFContext):
  def __init__(self):
    super(EFCFContext, self).__init__()
    self._changeset = None
    self._template_file = None

  @property
  def changeset(self):
    """True if the tool should generate a changeset rather than executing the change immediately"""
    return self._changeset

  @changeset.setter
  def changeset(self, value):
    if type(value) is not bool:
      raise TypeError("changeset value must be bool")
    self._changeset = value

  @property
  def template_file(self):
    """Path to the template file"""
    return self._template_file

  @template_file.setter
  def template_file(self, value):
    if type(value) is not str:
      raise TypeError("template file value must be str")
    self._template_file = value


def handle_args_and_set_context(args):
  """
  Args:
    args: the command line args, probably passed from main() as sys.argv[1:]
  Returns:
    a populated EFCFContext object (extends EFContext)
  Raises:
    IOError: if service registry file can't be found or can't be opened
    RuntimeError: if repo or branch isn't as spec'd in ef_config.EF_REPO and ef_config.EF_REPO_BRANCH
    CalledProcessError: if 'git rev-parse' command to find repo root could not be run
  """
  parser = argparse.ArgumentParser()
  parser.add_argument("template_file", help="/path/to/template_file.json")
  parser.add_argument("env", help=", ".join(EFConfig.ENV_LIST))
  parser.add_argument("--changeset", help="create a changeset; cannot be combined with --commit",
                      action="store_true", default=False)
  parser.add_argument("--commit", help="Make changes in AWS (dry run if omitted); cannot be combined with --changeset",
                      action="store_true", default=False)
  parser.add_argument("--sr", help="optional /path/to/service_registry_file.json", default=None)
  parser.add_argument("--verbose", help="Print additional info + resolved template", action="store_true", default=False)
  parser.add_argument("--devel", help="Allow running from branch; don't refresh from origin", action="store_true",
                      default=False)
  parsed_args = vars(parser.parse_args(args))
  context = EFCFContext()
  try:
    context.env = parsed_args["env"]
    context.template_file = parsed_args["template_file"]
  except ValueError as e:
    fail("Error in argument: {}".format(e.message))
  context.changeset = parsed_args["changeset"]
  context.commit = parsed_args["commit"]
  context.devel = parsed_args["devel"]
  context.verbose = parsed_args["verbose"]
  # Set up service registry and policy template path which depends on it
  context.service_registry = EFServiceRegistry(parsed_args["sr"])
  return context


def main():
  context = handle_args_and_set_context(sys.argv[1:])

  # argument sanity checks and contextual messages
  if context.commit and context.changeset:
    fail("Cannot use --changeset and --commit together")

  if context.changeset:
    print("=== CHANGESET ===\nCreating changeset only. See AWS GUI for changeset\n=== CHANGESET ===")
  elif not context.commit:
    print("=== DRY RUN ===\nValidation only. Use --commit to push template to CF\n=== DRY RUN ===")

  service_name = basename(splitext(context.template_file)[0])
  template_file_dir = dirname(context.template_file)
  # parameter file may not exist, but compute the name it would have if it did
  parameter_file_dir = template_file_dir + "/../parameters"
  parameter_file = parameter_file_dir + "/" + service_name + ".parameters." + context.env_full + ".json"

  # If running in EC2, use instance credentials (i.e. profile = None)
  # otherwise, use local credentials with profile name in .aws/credentials == account alias name
  if context.whereami == "ec2":
    profile = None
  else:
    profile = context.account_alias

  # Get service registry and refresh repo if appropriate
  try:
    if not (context.devel or getenv("JENKINS_URL", False)):
      pull_repo()
    else:
      print("not refreshing repo because --devel was set or running on Jenkins")
  except Exception as error:
    fail("Error: ", error)

  # Service must exist in service registry
  if context.service_registry.service_record(service_name) is None:
    fail("service: {} not found in service registry: {}".format(service_name, context.service_registry.filespec))

  if not context.env_full in context.service_registry.valid_envs(service_name):
    fail("Invalid environment: {} for service_name: {}\nValid environments are: {}" \
         .format(context.env_full, service_name, ", ".join(context.service_registry.valid_envs(service_name))))

  if context.verbose:
    print("service_name: {}".format(service_name))
    print("env: {}".format(context.env))
    print("env_full: {}".format(context.env_full))
    print("env_short: {}".format(context.env_short))
    print("template_file: {}".format(context.template_file))
    print("parameter_file: {}".format(parameter_file))
    if profile:
      print("profile: {}".format(profile))
    print("whereami: {}".format(context.whereami))
    print("service type: {}".format(context.service_registry.service_record(service_name)["type"]))

  # resolve {{SYMBOLS}} in the template file
  isfile(context.template_file) or fail("Not a file: {}".format(context.template_file))
  resolver = EFTemplateResolver(profile=profile, target_other=True, env=context.env, region=EFConfig.DEFAULT_REGION,
                                service=service_name, verbose=context.verbose)
  template_file_fh = open(context.template_file)
  resolver.load(template_file_fh)
  resolver.render()

  if context.verbose:
    print(resolver.template)

  if resolver.unresolved_symbols():
    fail("Unable to resolve symbols: " + ",".join(["{{"+s+"}}" for s in resolver.unresolved_symbols()]))

  dangling_left, dangling_right = resolver.count_braces()
  if dangling_left > 0 or dangling_right > 0:
    fail("Some {{ or }} were not resolved. left{{: {}, right}}: {}".format(dangling_left, dangling_right))

  # Create clients - if accessing by role, profile should be None
  try:
    clients = create_aws_clients(EFConfig.DEFAULT_REGION, profile, "cloudformation")
  except RuntimeError as error:
    fail("Exception creating clients in region {} with profile {}".format(EFConfig.DEFAULT_REGION, profile), error)

  stack_name = context.env + "-" + service_name
  try:
    stack_exists = clients["cloudformation"].describe_stacks(StackName=stack_name)
  except botocore.exceptions.ClientError:
    stack_exists = False

  # Load parameters from file
  if isfile(parameter_file):
    try:
      parameter_fh = open(parameter_file)
    except (OSError, IOError) as error:
      fail("Error opening and reading parameter file: {}".format(parameter_file), error)
    try:
      parameters = json.load(parameter_fh)
      parameter_fh.close()
    except ValueError as error:
      fail("JSON error in parameter file: {}".format(parameter_file, error))

    if context.verbose:
      print("parameters: {}".format(repr(parameters)))
  else:
    parameters = []

  # Validate rendered template before trying the stack operation
  if context.verbose:
    print("Validating template")
  try:
    clients["cloudformation"].validate_template(TemplateBody=resolver.template)
  except botocore.exceptions.ClientError as error:
    fail("Template did not pass validation", error)

  print("Template passed validation")

  # DO IT
  try:
    if context.changeset:
      print("Creating changeset: {}".format(stack_name))
      clients["cloudformation"].create_change_set(
        StackName=stack_name,
        TemplateBody=resolver.template,
        Parameters=parameters,
        Capabilities=['CAPABILITY_IAM'],
        ChangeSetName=stack_name,
        ClientToken=stack_name
      )
    elif context.commit:
      if stack_exists:
        print("Updating stack: {}".format(stack_name))
        clients["cloudformation"].update_stack(
          StackName=stack_name,
          TemplateBody=resolver.template,
          Parameters=parameters,
          Capabilities=['CAPABILITY_IAM']
        )
      else:
        print("Creating stack: {}".format(stack_name))
        clients["cloudformation"].create_stack(
          StackName=stack_name,
          TemplateBody=resolver.template,
          Parameters=parameters,
          Capabilities=['CAPABILITY_IAM']
        )
  except botocore.exceptions.ClientError as error:
    if error.response["Error"]["Message"] in "No updates are to be performed.":
      # Don't fail when there is no update to the stack
      print("No updates are to be performed.")
    else:
      fail("Error occurred when creating or updating stack", error)

if __name__ == "__main__":
  main()
