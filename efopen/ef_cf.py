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
import math
import os
import re
import subprocess
import sys
import time

import botocore.exceptions

from ef_config import EFConfig
from ef_context import EFContext
from ef_service_registry import EFServiceRegistry
from ef_template_resolver import EFTemplateResolver
from ef_utils import create_aws_clients, get_autoscaling_group_properties, fail
from ef_conf_utils import pull_repo

# CONSTANTS
# Cloudformation template size limit in bytes (which translates to the length of the template)
CLOUDFORMATION_SIZE_LIMIT = 51200

class EFCFContext(EFContext):
  def __init__(self):
    super(EFCFContext, self).__init__()
    self._changeset = None
    self._lint = None
    self._poll_status = None
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
  def lint(self):
    """True if the tool should lint the rendered template rather than uploading to cloudformation"""
    return self._lint

  @lint.setter
  def lint(self, value):
    if type(value) is not bool:
      raise TypeError("lint value must be bool")
    self._lint = value

  @property
  def poll_status(self):
    """True if the tool should poll for stack status"""
    return self._poll_status

  @poll_status.setter
  def poll_status(self, value):
    if type(value) is not bool:
      raise TypeError("poll_status value must be bool")
    self._poll_status = value

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
    RuntimeError: if branch isn't as spec'd in ef_config.EF_REPO_BRANCH
    CalledProcessError: if 'git rev-parse' command to find repo root could not be run
  """
  parser = argparse.ArgumentParser(description="Render cloudformation templates, create changesets, or update "
                                               "cloudformation stacks in an AWS account.")
  parser.add_argument("template_file", help="/path/to/template_file.json")
  parser.add_argument("env", help=", ".join(EFConfig.ENV_LIST))
  parser.add_argument("--sr", help="optional /path/to/service_registry_file.json", default=None)
  parser.add_argument("--verbose", help="Print additional info + resolved template", action="store_true", default=False)
  parser.add_argument("--devel", help="Allow running from branch; don't refresh from origin", action="store_true",
                      default=False)
  group = parser.add_mutually_exclusive_group()
  group.add_argument("--changeset", help="create a changeset; cannot be combined with --commit",
                      action="store_true", default=False)
  group.add_argument("--commit", help="Make changes in AWS (dry run if omitted); cannot be combined with --changeset",
                      action="store_true", default=False)
  group.add_argument("--lint", help="Execute cfn-lint on the rendered template", action="store_true",
                      default=False)
  group.add_argument("--render", help="Output resolved template", action="store_true", default=False)
  parser.add_argument("--percent", help="Specifies an override to the percentage of instances in an Auto Scaling rolling update (e.g. 10 for 10%%)",
                      type=int, default=False)
  parser.add_argument("--poll", help="Poll Cloudformation to check status of stack creation/updates",
                      action="store_true", default=False)
  parser.add_argument("--skip_symbols", help="Skip resolving the provided symbols", nargs='+', default=[])

  parsed_args = vars(parser.parse_args(args))
  context = EFCFContext()
  try:
    context.env = parsed_args["env"]
    context.template_file = parsed_args["template_file"]
  except ValueError as e:
    fail("Error in argument: {}".format(e))
  context.changeset = parsed_args["changeset"]
  context.commit = parsed_args["commit"]
  context.devel = parsed_args["devel"]
  context.lint = parsed_args["lint"]
  context.percent = parsed_args["percent"]
  context.poll_status = parsed_args["poll"]
  context.skip_symbols = parsed_args["skip_symbols"]
  context.verbose = parsed_args["verbose"]
  context.render = parsed_args["render"]
  # Set up service registry and policy template path which depends on it
  context.service_registry = EFServiceRegistry(parsed_args["sr"])
  return context

def resolve_template(template, profile, env, region, service, skip_symbols, verbose):
  # resolve {{SYMBOLS}} in the passed template file
  os.path.isfile(template) or fail("Not a file: {}".format(template))
  resolver = EFTemplateResolver(profile=profile, target_other=True, env=env,
                                region=region, service=service, skip_symbols=skip_symbols, verbose=verbose)
  with open(template) as template_file:
    resolver.load(template_file)
    resolver.render()

  if verbose:
    print(resolver.template)

  dangling_left, dangling_right = resolver.count_braces()
  if resolver.unresolved_symbols():
    fail("Unable to resolve symbols: " + ",".join(["{{" + s + "}}" for s in resolver.unresolved_symbols()]))
  elif dangling_left > 0 or dangling_right > 0:
    fail("Some {{ or }} were not resolved. left{{: {}, right}}: {}".format(dangling_left, dangling_right))
  else:
    return resolver.template


def is_stack_termination_protected_env(env):
  return env in EFConfig.STACK_TERMINATION_PROTECTED_ENVS


def enable_stack_termination_protection(clients, stack_name):
  clients["cloudformation"].update_termination_protection(
    EnableTerminationProtection=True,
    StackName=stack_name
  )

def calculate_max_batch_size(asg_client, service, percent):
  autoscaling_group_properties = get_autoscaling_group_properties(asg_client, service.split("-")[0], "-".join(service.split("-")[1:]))
  if not autoscaling_group_properties:
      # safe default
      return 1
  current_desired = autoscaling_group_properties[0]["DesiredCapacity"]
  new_batch_size = int(math.ceil(current_desired * (percent * 0.01)))
  # max batch size must be a minimum of 1, otherwise cloudformation gives an error.
  return max(new_batch_size, 1)

class CFTemplateLinter(object):

  def __init__(self, template):
    self.template = template
    self.work_dir = '.lint'
    self.local_template_path = os.path.join(self.work_dir, 'template.json')
    self.cfn_exit_code = None
    self.exit_code = None
    self.setup()

  def setup(self):
    if not os.path.exists(self.work_dir):
      os.mkdir(self.work_dir)

    with open(self.local_template_path, 'w') as f:
      f.write(self.template)

  def run_tests(self):
    self.cfn_lint()
    self.teardown()

  def cfn_lint(self):
    print("=== CLOUDFORMATION LINTING ===")
    cmd = 'cfn-lint --template {}'.format(self.local_template_path)
    cfn = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = cfn.communicate()
    print(stdout, stderr)
    if cfn.returncode in [0, 4]:
      print("Template passed CFN linting")
    self.cfn_exit_code = cfn.returncode

  def teardown(self):
    try:
      os.remove(self.local_template_path)
      os.rmdir(self.work_dir)
    except OSError as e:
      print("WARNING: Unable to remove local workdir or test-copy of template")
      print(e)
    self.exit_code = 1 if self.cfn_exit_code not in [0, 4] else 0  # Ignore cfn-lint warnings


def main():
  context = handle_args_and_set_context(sys.argv[1:])

  if context.changeset:
    print("=== CHANGESET ===\nCreating changeset only. See AWS GUI for changeset\n=== CHANGESET ===")
  elif not context.commit and not context.render:
    print("=== DRY RUN ===\nValidation only. Use --commit to push template to CF\n=== DRY RUN ===")

  service_name = os.path.basename(os.path.splitext(context.template_file)[0])
  template_file_dir = os.path.dirname(context.template_file)
  # parameter file may not exist, but compute the name it would have if it did
  parameter_file_dir = template_file_dir + "/../parameters"
  parameter_file = parameter_file_dir + "/" + service_name + ".parameters." + context.env_full + ".json"

  # If running in EC2, use instance credentials (i.e. profile = None)
  # unless it's a non-EC2, which means that we use local
  # credentials with profile name in .aws/credentials == account alias name
  if context.whereami == "ec2":
    profile = None
  else:
    profile = context.account_alias

  # Get service registry and refresh repo if appropriate
  try:
    if not context.devel and context.whereami != 'jenkins':
      pull_repo()
  except Exception as error:
    fail("Error: ", error)

  # Service must exist in service registry
  if context.service_registry.service_record(service_name) is None:
    fail("service: {} not found in service registry: {}".format(service_name, context.service_registry.filespec))

  if not context.env_full in context.service_registry.valid_envs(service_name):
    fail("Invalid environment: {} for service_name: {}\nValid environments are: {}" \
         .format(context.env_full, service_name, ", ".join(context.service_registry.valid_envs(service_name))))

  if context.percent and (context.percent <= 0 or context.percent > 100):
    fail("Percent value cannot be less than or equal to 0 and greater than 100")

  # Set the region found in the service_registry. Default is EFConfig.DEFAULT_REGION if region key not found
  region = context.service_registry.service_region(service_name)

  if context.verbose:
    print("service_name: {}".format(service_name))
    print("env: {}".format(context.env))
    print("env_full: {}".format(context.env_full))
    print("env_short: {}".format(context.env_short))
    print("region: {}".format(region))
    print("template_file: {}".format(context.template_file))
    print("parameter_file: {}".format(parameter_file))
    if profile:
      print("profile: {}".format(profile))
    print("whereami: {}".format(context.whereami))
    print("service type: {}".format(context.service_registry.service_record(service_name)["type"]))

  template = resolve_template(
    template=context.template_file,
    profile=profile,
    env=context.env,
    region=region,
    service=service_name,
    skip_symbols=context.skip_symbols,
    verbose=context.verbose
  )

  if context.render:
    print(template)
    exit()

  # Create clients - if accessing by role, profile should be None
  try:
    clients = create_aws_clients(region, profile, "cloudformation", "autoscaling")
  except RuntimeError as error:
    fail("Exception creating clients in region {} with profile {}".format(region, profile), error)

  stack_name = context.env + "-" + service_name
  try:
    stack_exists = clients["cloudformation"].describe_stacks(StackName=stack_name)
  except botocore.exceptions.ClientError:
    stack_exists = False

  # Load parameters from file
  if os.path.isfile(parameter_file):
    parameters_template = resolve_template(
      template=parameter_file,
      profile=profile,
      env=context.env,
      region=region,
      service=service_name,
      skip_symbols=context.skip_symbols,
      verbose=context.verbose
    )
    try:
      parameters = json.loads(parameters_template)
    except ValueError as error:
      fail("JSON error in parameter file: {}".format(parameter_file, error))
  else:
    parameters = []

  if context.percent:
    print("Modifying deploy rate to {}%".format(context.percent))
    modify_template = json.loads(template)
    for key in modify_template["Resources"]:
      if modify_template["Resources"][key]["Type"] == "AWS::AutoScaling::AutoScalingGroup":
        if "UpdatePolicy" in modify_template["Resources"][key]:
          autoscaling_group = modify_template["Resources"][key]["Properties"]
          service = autoscaling_group["Tags"][0]["Value"]
          autoscaling_group_properties = get_autoscaling_group_properties(clients["autoscaling"], service.split("-")[0], "-".join(service.split("-")[1:]))
          new_max_batch_size = calculate_max_batch_size(clients["autoscaling"], service, context.percent)
          modify_template["Resources"][key]["UpdatePolicy"]["AutoScalingRollingUpdate"]["MaxBatchSize"] = new_max_batch_size
          current_desired = autoscaling_group_properties[0]["DesiredCapacity"] if autoscaling_group_properties else "missing"
          print("Service {} [current desired: {}, calculated max batch size: {}]".format(
                service, current_desired, new_max_batch_size))
    template = json.dumps(modify_template)

  # Detect if the template exceeds the maximum size that is allowed by Cloudformation
  if len(template) > CLOUDFORMATION_SIZE_LIMIT:
    # Compress the generated template by removing whitespaces
    print("Template exceeds the max allowed length that Cloudformation will accept. Compressing template...")
    print("Uncompressed size of template: {}".format(len(template)))
    unpacked = json.loads(template)
    template = json.dumps(unpacked, separators=(",", ":"))
    print("Compressed size of template: {}".format(len(template)))

  # Validate rendered template before trying the stack operation
  if context.verbose:
    print("Validating template")
  try:
    clients["cloudformation"].validate_template(TemplateBody=template)
    json.loads(template)  # Tests for valid JSON syntax, oddly not handled above
  except botocore.exceptions.ClientError as error:
    fail("Template did not pass validation", error)
  except ValueError as e:  # includes simplejson.decoder.JSONDecodeError
    fail('Failed to decode JSON', e)

  print("Template passed validation")

  # DO IT
  try:
    if context.changeset:
      print("Creating changeset: {}".format(stack_name))
      results = clients["cloudformation"].create_change_set(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=parameters,
        Capabilities=['CAPABILITY_AUTO_EXPAND', 'CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
        ChangeSetName=stack_name,
        ClientToken=stack_name
      )
      if is_stack_termination_protected_env(context.env):
        enable_stack_termination_protection(clients, stack_name)
      results_ids = {key: value for key, value in results.iteritems()
                     if key in ('Id', 'StackId')}
      print("Changeset Info: {}".format(json.dumps(results_ids)))
    elif context.commit:
      if stack_exists:
        print("Updating stack: {}".format(stack_name))
        clients["cloudformation"].update_stack(
          StackName=stack_name,
          TemplateBody=template,
          Parameters=parameters,
          Capabilities=['CAPABILITY_AUTO_EXPAND', 'CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
        )
        if is_stack_termination_protected_env(context.env):
          enable_stack_termination_protection(clients, stack_name)
      else:
        print("Creating stack: {}".format(stack_name))
        clients["cloudformation"].create_stack(
          StackName=stack_name,
          TemplateBody=template,
          Parameters=parameters,
          Capabilities=['CAPABILITY_AUTO_EXPAND', 'CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
        )
        if is_stack_termination_protected_env(context.env):
          enable_stack_termination_protection(clients, stack_name)
      if context.poll_status:
        while True:
          stack_status = clients["cloudformation"].describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
          if context.verbose:
            print("{}".format(stack_status))
          if stack_status.endswith('ROLLBACK_COMPLETE'):
            print("Stack went into rollback with status: {}".format(stack_status))
            sys.exit(1)
          elif re.match(r".*_COMPLETE(?!.)", stack_status) is not None:
            break
          elif re.match(r".*_FAILED(?!.)", stack_status) is not None:
            print("Stack failed with status: {}".format(stack_status))
            sys.exit(1)
          elif re.match(r".*_IN_PROGRESS(?!.)", stack_status) is not None:
            time.sleep(EFConfig.EF_CF_POLL_PERIOD)
    elif context.lint:
      tester = CFTemplateLinter(template)
      tester.run_tests()
      exit(tester.exit_code)

  except botocore.exceptions.ClientError as error:
    if error.response["Error"]["Message"] in "No updates are to be performed.":
      # Don't fail when there is no update to the stack
      print("No updates are to be performed.")
    else:
      fail("Error occurred when creating or updating stack", error)

if __name__ == "__main__":
  main()
