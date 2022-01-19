#!/usr/bin/env python

"""
For one environment:
- Step through all services in the service registry
- If a security group and/or role named "<env>-<service>" is needed in the current account and
environment, make it.
- Make EC2 instance profiles as needed as well.
- Bind policies from policy_templates to roles if "policies" key is present.
- Override default AssumeRole policy if assume_role_policy key is present.

If --commit flag is not set, only a dry run occurs; no changes are made.


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
from os.path import dirname, normpath
import sys
import time

from botocore.exceptions import ClientError

from ef_aws_resolver import EFAwsResolver
from ef_config import EFConfig
from ef_context import EFContext
from ef_service_registry import EFServiceRegistry
from ef_template_resolver import EFTemplateResolver
from ef_utils import create_aws_clients, fail, get_account_id, http_get_metadata
from ef_conf_utils import pull_repo

# Globals
CLIENTS = None
CONTEXT = None
AWS_RESOLVER = None

# list of service_registry_file "service types" that this tool handles. Skip unlisted types
SUPPORTED_SERVICE_TYPES = [
  "aws_cloudtrail",
  "aws_ec2",
  "aws_ecs",
  "aws_ecs_http",
  "aws_fixture",
  "aws_lambda",
  "aws_role",
  "aws_security_group",
  "http_service"
]

# list of service_registry_file "service types" that are allowed in the global env
GLOBAL_SERVICE_TYPES = [
  "aws_cloudtrail",
  "aws_fixture",
  "aws_lambda",
  "aws_role"
]

# these Service Registry types get Roles
# If value is not None, the role can get a default AssumeRolePolicy document listing that AWS service as principal
# If value is None, the service registry entry must include "assume_role_policy": with an AssumeRole policy doc
SERVICE_TYPE_ROLE = {
  "aws_cloudtrail": "cloudtrail.amazonaws.com",
  "aws_ec2": "ec2.amazonaws.com",
  "aws_ecs": ["ecs.amazonaws.com", "ecs-tasks.amazonaws.com"],
  "aws_ecs_http": ["ecs.amazonaws.com", "ecs-tasks.amazonaws.com"],
  "aws_lambda": "lambda.amazonaws.com",
  "aws_role": None, # Bare role requires a custom assume role policy ("assume_role_policy": "name_of_policy")
  "http_service": "ec2.amazonaws.com"
}

# these service types get Security Groups
SG_SERVICE_TYPES = [
  "aws_ec2",
  "aws_ecs",
  "aws_ecs_http",
  "aws_lambda",
  "aws_security_group",
  "http_service"
]

# these service types get instance profiles (they have EC2 instances)
INSTANCE_PROFILE_SERVICE_TYPES = [
  "aws_ec2",
  "aws_ecs",
  "aws_ecs_http",
  "http_service"
]

# these service types get KMS Keys
KMS_SERVICE_TYPES = [
  "aws_ec2",
  "aws_ecs",
  "aws_ecs_http",
  "aws_fixture",
  "aws_lambda",
  "http_service"
]

# Utilities
def handle_args_and_set_context(args):
  """
  Args:
    args: the command line args, probably passed from main() as sys.argv[1:]
  Returns:
    a populated EFContext object
  Raises:
    IOError: if service registry file can't be found or can't be opened
    RuntimeError: if branch isn't as spec'd in ef_config.EF_REPO_BRANCH
    CalledProcessError: if 'git rev-parse' command to find repo root could not be run
  """
  parser = argparse.ArgumentParser(
    description="Generate a security group, IAM role, instance profile, attache managed, custom, or inline "
                "generated policies to a role, create KMS keys, and create newrelic alerts for a service based "
                "on the information specified in the service_registry.json.")
  parser.add_argument("env", help=", ".join(EFConfig.ENV_LIST))
  parser.add_argument("--sr", help="optional: /path/to/service_registry_file.json", default=None)
  parser.add_argument("--commit", help="Make changes in AWS (dry run if omitted)", action="store_true", default=False)
  parser.add_argument("--verbose", help="Print additional info", action="store_true", default=False)
  parser.add_argument("--devel", help="Allow running from branch; don't refresh from origin", action="store_true",
                      default=False)
  parser.add_argument("--only_for", help="optional: run ef-generate for a only specific entry in the service registry", default=None)
  parsed_args = vars(parser.parse_args(args))
  context = EFContext()
  context.commit = parsed_args["commit"]
  context.devel = parsed_args["devel"]
  try:
    context.env = parsed_args["env"]
  except ValueError as e:
    fail("Error in env: {}".format(e))
  # Set up service registry and policy template path which depends on it
  context.service_registry = EFServiceRegistry(parsed_args["sr"])
  context.policy_template_path = normpath(dirname(context.service_registry.filespec)) + EFConfig.POLICY_TEMPLATE_PATH_SUFFIX
  context.verbose = parsed_args["verbose"]
  context.only_for = parsed_args["only_for"]
  return context

def print_if_verbose(message):
  if CONTEXT.verbose:
    print(message, file=sys.stderr)

def get_role_id(target_name):
  """
  Args:
    target_name: the name of the role to look up
  Returns:
    role ID if target_name found, False otherwise
  """
  try:
    role = CLIENTS["iam"].get_role(RoleName=target_name)
  except:
    return False
  return role["Role"]["RoleId"]

def get_instance_profile(instance_profile_name):
  """
  Args:
    instance_profile_name: the name of the instance profile to look up
  Returns:
    an instance profile if target_name found, False otherwise
  """
  try:
    instance_profile = CLIENTS["iam"].get_instance_profile(InstanceProfileName=instance_profile_name)
  except:
    return False
  return instance_profile

def instance_profile_contains_role(instance_profile, role_name):
  """
  Args:
    instance_profile: the instance profile to check
    role_name: the name of the role to look for
  Returns:
    True if role_name is inside instance_profile, False otherwise
  """
  for role in instance_profile["InstanceProfile"]["Roles"]:
    if role["RoleName"] == role_name:
      return True
    return False

def resolve_policy_document(policy_name):
  policy_filename = "{}{}.json".format(CONTEXT.policy_template_path, policy_name)
  print_if_verbose("Load policy: {} from file: {}".format(policy_name, policy_filename))
  # retrieve policy template
  try:
    policy_file = file(policy_filename, 'r')
    policy_template = policy_file.read()
    policy_file.close()
  except:
    fail("error opening policy file: {}".format(policy_filename))
  print_if_verbose("pre-resolution policy template:\n{}".format(policy_template))
  # If running in EC2, do not set profile and set target_other=True
  if CONTEXT.whereami == "ec2":
    resolver = EFTemplateResolver(target_other=True, env=CONTEXT.env, region=EFConfig.DEFAULT_REGION,
                                  service=CONTEXT.service, verbose=CONTEXT.verbose)
  else:
    resolver = EFTemplateResolver(profile=CONTEXT.account_alias, env=CONTEXT.env, region=EFConfig.DEFAULT_REGION,
                                service=CONTEXT.service, verbose=CONTEXT.verbose)
  resolver.load(policy_template)
  policy_document = resolver.render()
  print_if_verbose("resolved policy document:\n{}".format(policy_document))
  if not resolver.resolved_ok():
    fail("policy template {} has unresolved symbols or extra {{ or }}: {}".format(
      policy_filename, resolver.unresolved_symbols()))
  return policy_document

def conditionally_create_security_groups(env, service_name, service_type):
  """
  Create security groups as needed; name and number created depend on service_type
  Args:
    env: the environment the SG will be created in
    service_name: name of the service in service registry
    service_type: service registry service type: 'aws_ec2', 'aws_ecs', 'aws_ecs_http',
                                 'aws_lambda', 'aws_security_group', or 'http_service'
  """
  if service_type not in SG_SERVICE_TYPES:
    print_if_verbose("not eligible for security group(s); service type: {}".format(service_type))
    return

  target_name = "{}-{}".format(env, service_name)
  if service_type == "aws_ec2":
    sg_names = ["{}-ec2".format(target_name)]
  elif service_type == "aws_ecs":
    sg_names = ["{}-ecs".format(target_name)]
  elif service_type == "aws_lambda":
    sg_names = ["{}-lambda".format(target_name)]
  elif service_type == "http_service":
    sg_names = [
      "{}-ec2".format(target_name),
      "{}-elb".format(target_name)
    ]
  elif service_type == "aws_ecs_http":
    sg_names = [
      "{}-ecs".format(target_name),
      "{}-elb".format(target_name)
    ]
  elif service_type == "aws_security_group":
    sg_names = [target_name]
  else:
    fail("Unexpected service_type: {} when creating security group for: {}".format(service_type, target_name))

  for sg_name in sg_names:
    if not AWS_RESOLVER.ec2_security_group_security_group_id(sg_name):
      vpc_name = "vpc-{}".format(env)
      print("Create security group: {} in vpc: {}".format(sg_name, vpc_name))
      vpc = AWS_RESOLVER.ec2_vpc_vpc_id(vpc_name)
      if not vpc:
        fail("Error: could not get VPC by name: {}".format(vpc_name))
      # create security group
      if CONTEXT.commit:
        try:
          new_sg = CLIENTS["ec2"].create_security_group(GroupName=sg_name, VpcId=vpc, Description=sg_name)
        except:
          fail("Exception creating security group named: {} in VpcId: {}".format(sg_name, vpc_name), sys.exc_info())
        print(new_sg["GroupId"])
    else:
      print_if_verbose("security group already exists: {}".format(sg_name))

def conditionally_create_role(role_name, sr_entry, tags=None):
  """
  Create role_name if a role by that name does not already exist; attach a custom list of Principals
  to its AssumeRolePolicy
  Args:
    role_name: the name for the role to create
    sr_entry: service registry entry

  Example of a (complex) AssumeRole policy document comprised of two IAM entities and a service:
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ec2.amazonaws.com",
          "AWS": [
            "arn:aws:iam::978969509086:root",
            "arn:aws:iam::978969509086:role/mgmt-jenkins"
          ]
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }
  """
  service_type = sr_entry['type']
  if service_type not in SERVICE_TYPE_ROLE:
    print_if_verbose("not eligible for role (and possibly instance profile); service type: {}".format(service_type))
    return

  if "assume_role_policy" in sr_entry:
    # Explicitly defined AssumeRole policy
    assume_role_policy_document = resolve_policy_document(sr_entry["assume_role_policy"])
  else:
    # Create Service:AssumeRole policy using the service type in the SERVICE_TYPE_ROLE dict
    # which must list a service type to use this capacity (most do)
    if SERVICE_TYPE_ROLE[service_type] is None:
      fail("service_type: {} does not have a default service-type AssumeRole policy".format(service_type))
    service_principals = {"Service": SERVICE_TYPE_ROLE[service_type]}
    assume_role_policy = {
      "Version" : "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": service_principals,
        "Action": [ "sts:AssumeRole" ]
      }]
    }
    assume_role_policy_document = json.dumps(assume_role_policy, indent=2)
  if not get_role_id(role_name):
    print("Create role: {}".format(role_name))
    print_if_verbose("AssumeRole policy document:\n{}".format(assume_role_policy_document))
    if CONTEXT.commit:
      try:
        new_role = CLIENTS["iam"].create_role(
          RoleName=role_name, AssumeRolePolicyDocument=assume_role_policy_document, Tags=tags or []
        )
      except ClientError as error:
        fail("Exception creating new role named: {} {}".format(role_name, sys.exc_info(), error))
      print(new_role["Role"]["RoleId"])
  else:
    print_if_verbose("role already exists: {}".format(role_name))

def conditionally_create_profile(role_name, service_type):
  """
  Check that there is a 1:1 correspondence with an InstanceProfile having the same name
  as the role, and that the role is contained in it. Create InstanceProfile and attach to role if needed.
  """
  # make instance profile if this service_type gets an instance profile
  if service_type not in INSTANCE_PROFILE_SERVICE_TYPES:
    print_if_verbose("service type: {} not eligible for instance profile".format(service_type))
    return

  instance_profile = get_instance_profile(role_name)
  if not instance_profile:
    print("Create instance profile: {}".format(role_name))
    if CONTEXT.commit:
      try:
        instance_profile = CLIENTS["iam"].create_instance_profile(InstanceProfileName=role_name)
      except ClientError as error:
        fail("Exception creating instance profile named: {} {}".format(role_name, sys.exc_info(), error))
  else:
    print_if_verbose("instance profile already exists: {}".format(role_name))
  # attach instance profile to role; test 'if instance_profile' because we drop through to here in a dry run
  if instance_profile and not instance_profile_contains_role(instance_profile, role_name):
    print("Add role: {} to instance profile: {}".format(role_name, role_name))
    if CONTEXT.commit:
      try:
        CLIENTS["iam"].add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
      except ClientError as error:
        fail("Exception adding role to instance profile: {} {}".format(role_name, sys.exc_info(), error))
  else:
    print_if_verbose("instance profile already contains role: {}".format(role_name))


def get_managed_policy_arn(policy_name):
  """
  Retrieves the ARN of an AWS managed policy specified in the aws_managed_policies field of the service_registry.
  Args:
    policy_name: name of the policy whose ARN we want to retrieve
  Raises:
    NameError: no ARN could be found for the specified policy name
  """
  try:
    arn = 'arn:aws:iam::aws:policy/{}'.format(policy_name)
    CLIENTS["iam"].get_policy(PolicyArn=arn)
    return arn
  except CLIENTS["iam"].exceptions.NoSuchEntityException:
    pass

  role_types = ['job-function', 'service-role']
  for type in role_types:
    arn = 'arn:aws:iam::aws:policy/{}/{}'.format(type, policy_name)
    try:
      CLIENTS["iam"].get_policy(PolicyArn=arn)
      return arn
    except CLIENTS["iam"].exceptions.NoSuchEntityException:
      continue

  raise NameError


def conditionally_attach_aws_managed_policies(role_name, sr_entry):
  """
  If 'aws_managed_policies' key lists the names of AWS managed policies to bind to the role,
  attach them to the role
  Args:
    role_name: name of the role to attach the policies to
    sr_entry: service registry entry
  """
  service_type = sr_entry['type']
  if not (service_type in SERVICE_TYPE_ROLE and "aws_managed_policies" in sr_entry):
    print_if_verbose("not eligible for policies; service_type: {} is not valid for policies "
                     "or no 'aws_managed_policies' key in service registry for this role".format(service_type))
    return

  for policy_name in sr_entry['aws_managed_policies']:
    print_if_verbose("loading policy: {} for role: {}".format(policy_name, role_name))

    if CONTEXT.commit:
      try:
        policy_arn = get_managed_policy_arn(policy_name)
      except NameError:
        fail("Exception attaching managed policy '{}'. Could not retrieve policy arn.".format(policy_name))

      try:
        CLIENTS["iam"].attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
      except:
        fail("Exception putting policy: {} onto role: {}".format(policy_name, role_name), sys.exc_info())

      print_if_verbose("Attached managed policy '{}'".format(policy_name))


def conditionally_attach_customer_managed_policies(role_name, sr_entry):
  """
  If 'customer_managed_policies' key lists the names of customer managed policies to bind to the role,
  attach them to the role.

  Note that this function will throw a warning without failing, if the managed policy does not exist in
  the given account.
  Args:
    role_name: name of the role to attach the policies to
    sr_entry: service registry entry
  """
  service_type = sr_entry['type']
  if not (service_type in SERVICE_TYPE_ROLE and "customer_managed_policies" in sr_entry):
    print_if_verbose("not eligible for policies; service_type: {} is not valid for policies "
                     "or no 'customer_managed_policies' key in service registry for this role".format(service_type))
    return

  for policy_name in sr_entry['customer_managed_policies']:
    print_if_verbose("loading policy: {} for role: {}".format(policy_name, role_name))

    if CONTEXT.commit:
      policy_arn = 'arn:aws:iam::{}:policy/{}'.format(CONTEXT.account_id, policy_name)
      try:
        CLIENTS["iam"].attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
      except CLIENTS["iam"].exceptions.NoSuchEntityException as exc:
        print("WARNING: {}".format(exc))
      except:
        fail("Exception putting policy: {} onto role: {}".format(policy_name, role_name), sys.exc_info())

def conditionally_inline_policies(role_name, sr_entry):
  """
  If 'policies' key lists the filename prefixes of policies to bind to the role,
  load them from the expected path and inline them onto the role
  Args:
    role_name: name of the role to attach the policies to
    sr_entry: service registry entry
  """
  service_type = sr_entry['type']
  if not (service_type in SERVICE_TYPE_ROLE and "policies" in sr_entry):
    print_if_verbose("not eligible for policies; service_type: {} is not valid for policies "
                     "or no 'policies' key in service registry for this role".format(service_type))
    return

  for policy_name in sr_entry['policies']:
    print_if_verbose("loading policy: {} for role: {}".format(policy_name, role_name))
    try:
      policy_document = resolve_policy_document(policy_name)
    except:
      fail("Exception loading policy: {} for role: {}".format(policy_name, role_name), sys.exc_info())

    # inline the policy onto the role
    if CONTEXT.commit:
      try:
        CLIENTS["iam"].put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_document)
      except:
        fail("Exception putting policy: {} onto role: {}".format(policy_name, role_name), sys.exc_info())

def conditionally_create_kms_key(role_name, service_type):
  """
  Create KMS Master Key for encryption/decryption of sensitive values in cf templates and latebind configs
  Args:
      role_name: name of the role that kms key is being created for; it will be given decrypt privileges.
      service_type: service registry service type: 'aws_ec2', 'aws_ecs', 'aws_ecs_http', 'aws_fixture',
                                                   'aws_lambda', or 'http_service'
  """
  if service_type not in KMS_SERVICE_TYPES:
    print_if_verbose("not eligible for kms; service_type: {} is not valid for kms".format(service_type))
    return

  # Converting all periods to underscores because they are invalid in KMS alias names
  key_alias = role_name.replace('.', '_')

  try:
    kms_key = CLIENTS["kms"].describe_key(KeyId='alias/{}'.format(key_alias))
  except ClientError as error:
    if error.response['Error']['Code'] == 'NotFoundException':
      kms_key = None
    else:
      fail("Exception describing KMS key: {} {}".format(role_name, error))

  account_id = CONTEXT.account_id
  if service_type == "aws_fixture":
    kms_key_policy = {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "Enable IAM User Permissions",
          "Effect": "Allow",
          "Principal": {
            "AWS": "arn:aws:iam::{}:root".format(account_id)
          },
          "Action": "kms:*",
          "Resource": "*"
        }
      ]
    }
  else:
    role_principal = [ "arn:aws:iam::{}:role/{}".format(account_id, role_name) ]
    if '.' not in role_name:
      subservice_principals = "arn:aws:iam::{}:role/{}.*".format(account_id, role_name)
      role_principal.append(subservice_principals)
    kms_key_policy = {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "Enable IAM User Permissions",
          "Effect": "Allow",
          "Principal": {
            "AWS": "arn:aws:iam::{}:root".format(account_id)
          },
          "Action": "kms:*",
          "Resource": "*"
        },
        {
          "Sid": "Allow Service Role Decrypt Privileges",
          "Effect": "Allow",
          "Principal": "*",
          "Action": "kms:Decrypt",
          "Resource": "*",
          "Condition": {
                "ForAnyValue:StringLike": {
                    "aws:PrincipalArn": role_principal
                }
            }
        },
        {
          "Sid": "Allow use of the key for default autoscaling group service role",
          "Effect": "Allow",
          "Principal": { "AWS": "arn:aws:iam::{}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling".format(account_id) },
          "Action": [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:DescribeKey"
          ],
          "Resource": "*"
        },
        {
          "Sid": "Allow attachment of persistent resourcesfor default autoscaling group service role",
          "Effect": "Allow",
          "Principal": { "AWS": "arn:aws:iam::{}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling".format(account_id) },
          "Action": [
            "kms:CreateGrant"
          ],
          "Resource": "*",
          "Condition": {
            "Bool": {
              "kms:GrantIsForAWSResource": True
            }
          }
        }
      ]
    }

  if not kms_key:
    print("Create KMS key: {}".format(key_alias))
    if CONTEXT.commit:
      # Create KMS Master Key. Due to AWS eventual consistency a newly created IAM role may not be
      # immediately visible to KMS. Retrying up to 5 times (25 seconds) to account for this behavior.
      create_key_failures = 0
      while create_key_failures <= 5:
        try:
          kms_key = CLIENTS["kms"].create_key(
            Policy=json.dumps(kms_key_policy, indent=4),
            Description='Master Key for {}'.format(role_name)
          )
          break
        except ClientError as error:
          if error.response['Error']['Code'] == 'MalformedPolicyDocumentException':
            if create_key_failures == 5:
              fail("Exception creating kms key: {} {}".format(role_name, error))
            else:
              create_key_failures += 1
              time.sleep(5)
          else:
            fail("Exception creating kms key: {} {}".format(role_name, error))

      # Assign key an alias. This is used for all future references to it (rather than the key ARN)
      try:
        CLIENTS["kms"].create_alias(
          AliasName='alias/{}'.format(key_alias),
          TargetKeyId=kms_key['KeyMetadata']['KeyId']
        )
      except ClientError as error:
        fail("Exception creating alias for kms key: {} {}".format(role_name, error))
  else:
    print_if_verbose("KMS key already exists: {}".format(key_alias))

  # Enable KMS key rotation
  if CONTEXT.commit:
    try:
      CLIENTS["kms"].enable_key_rotation(KeyId=kms_key["KeyMetadata"]["KeyId"])
    except ClientError as error:
      fail("Error in enabling key rotation: {} {}".format(role_name, error))


def conditionally_create_blackhole_target_groups(env, target_name, service_type, sr_entry):
  if service_type != "http_service":
    print_if_verbose("skipping black hole target group creation, {} is not an http_service".format(target_name))
    return

  # Checking for a short_name field in case of service's with a long name due to a 32 character limit on target groups.
  # The longest a service name can be is 19 characters because it will be prefixed with '{{ENV}}-' and suffixed with '-i-bh'
  if "short_name" in sr_entry:
    target_group_name = "{}-{}".format(env, sr_entry["short_name"])
  else:
    target_group_name = target_name

  # Periods are not a valid character in target group names
  target_group_name = target_group_name.replace('.', '-')

  vpc_name = "vpc-{}".format(env)
  vpc_id = AWS_RESOLVER.ec2_vpc_vpc_id(vpc_name)

  if CONTEXT.commit:
    print_if_verbose("Creating {} blackhole target groups".format(target_name))
    try:
      CLIENTS["elbv2"].create_target_group(
        Name="{}-i-bh".format(target_group_name),
        Protocol='HTTP',
        Port=8080,
        VpcId=vpc_id,
        Tags=[
          {
            'Key': 'Service',
            'Value': target_name
          },
        ]
      )
      CLIENTS["elbv2"].create_target_group(
        Name="{}-e-bh".format(target_group_name),
        Protocol='HTTP',
        Port=8080,
        VpcId=vpc_id,
        Tags=[
           {
             'Key': 'Service',
             'Value': target_name
           },
         ]
      )
    except ClientError as error:
      fail("Error creating {} blackhole target groups\n{}".format(target_name, error))


def create_newrelic_alerts():
  """
   Create Newrelic Alerts for each entry in the service registry application_services
   Note: Import is inside this function rather than top of the file so that we do not import when running unit tests.
         (would otherwise require an ef_site_config.yml in the directory where tests are being run)
  """
  from newrelic_executor import NewRelicAlerts
  print("> Creating NewRelic Alerts")
  NewRelicAlerts(CONTEXT, CLIENTS).run()

def main():
  global CONTEXT, CLIENTS, AWS_RESOLVER

  CONTEXT = handle_args_and_set_context(sys.argv[1:])
  if not CONTEXT.devel and CONTEXT.whereami != 'jenkins':
    try:
      pull_repo()
    except RuntimeError as error:
      fail("Error checking or pulling repo", error)
  else:
    print("Not refreshing repo because --devel was set or running on Jenkins")

  # sign on to AWS and create clients and get account ID
  try:
    # If running in EC2, always use instance credentials. One day we'll have "lambda" in there too, so use "in" w/ list
    if CONTEXT.whereami == "ec2":
      CLIENTS = create_aws_clients(EFConfig.DEFAULT_REGION, None, "cloudfront", "ec2", "elbv2", "iam", "kms")
      CONTEXT.account_id = str(json.loads(http_get_metadata('iam/info'))["InstanceProfileArn"].split(":")[4])
    else:
      # Otherwise, we use local user creds based on the account alias
      CLIENTS = create_aws_clients(EFConfig.DEFAULT_REGION, CONTEXT.account_alias, "cloudfront", "ec2", "elbv2", "iam", "kms", "sts")
      CONTEXT.account_id = get_account_id(CLIENTS["sts"])
  except RuntimeError:
    fail("Exception creating AWS clients in region {} with profile {}".format(
      EFConfig.DEFAULT_REGION, CONTEXT.account_alias))
  # Instantiate an AWSResolver to lookup AWS resources
  AWS_RESOLVER = EFAwsResolver(CLIENTS)

  # Show where we're working
  if not CONTEXT.commit:
    print("=== DRY RUN ===\nUse --commit to create roles and security groups\n=== DRY RUN ===")
  print("env: {}".format(CONTEXT.env))
  print("env_full: {}".format(CONTEXT.env_full))
  print("env_short: {}".format(CONTEXT.env_short))
  print("aws account profile: {}".format(CONTEXT.account_alias))
  print("aws account number: {}".format(CONTEXT.account_id))

  # If we're only ef-generate for a specific service, print it out here
  if CONTEXT.only_for:
    print("running ef-generate only for entry: {}".format(CONTEXT.only_for))

  # Step through all services in the service registry
  for CONTEXT.service in CONTEXT.service_registry.iter_services():
    service_name = CONTEXT.service[0]
    target_name = "{}-{}".format(CONTEXT.env, service_name)
    sr_entry = CONTEXT.service[1]
    service_type = sr_entry['type']
    print_if_verbose("service: {} in env: {}".format(service_name, CONTEXT.env))

    # Are we targeting a specific entry in the registry?
    if CONTEXT.only_for and CONTEXT.only_for != service_name:
      continue

    # Is this service_type handled by this tool?
    if service_type not in SUPPORTED_SERVICE_TYPES:
      print_if_verbose("unsupported service type: {}".format(service_type))
      continue
    # Is the env valid for this service?
    if CONTEXT.env_full not in CONTEXT.service_registry.valid_envs(service_name):
      print_if_verbose("env: {} not valid for service {}".format(CONTEXT.env_full, service_name))
      continue
    # Is the service_type allowed in 'global'?
    if CONTEXT.env == "global" and service_type not in GLOBAL_SERVICE_TYPES:
      print_if_verbose("env: {} not valid for service type {}".format(CONTEXT.env, service_type))
      continue

    # 1. CONDITIONALLY MAKE ROLE AND/OR INSTANCE PROFILE FOR THE SERVICE
    # If service gets a role, create with either a custom or default AssumeRole policy document
    conditionally_create_role(target_name, sr_entry, tags=sr_entry.get('tags'))
    # Instance profiles and security groups are not allowed in the global scope
    if CONTEXT.env != "global":
      conditionally_create_profile(target_name, service_type)

      # 2. SECURITY GROUP(S) FOR THE SERVICE : only some types of services get security groups
      conditionally_create_security_groups(CONTEXT.env, service_name, service_type)

    # 3. KMS KEY FOR THE SERVICE : only some types of services get kms keys
    conditionally_create_kms_key(target_name, service_type)

    # 4. ATTACH AWS MANAGED POLICIES TO ROLE
    conditionally_attach_aws_managed_policies(target_name, sr_entry)

    # 5. ATTACH CUSTOMER MANAGED POLICIES TO ROLE
    conditionally_attach_customer_managed_policies(target_name, sr_entry)

    # 6. INLINE SERVICE'S POLICIES INTO ROLE
    # only eligible service types with "policies" sections in the service registry get policies
    conditionally_inline_policies(target_name, sr_entry)

    # 7. CREATE BLACKHOLE TARGET GROUPS FOR SERVICES WITH A LOAD BALANCER
    conditionally_create_blackhole_target_groups(CONTEXT.env, target_name, service_type, sr_entry)

    # Break from the loop if we've finished working on the targeted entry
    if CONTEXT.only_for:
      break

  # Create newrelic alerts for all "application_services" in the service registry
  if "newrelic" in EFConfig.PLUGINS:
    create_newrelic_alerts()

  print("Exit: success")


if __name__ == "__main__":
  main()
