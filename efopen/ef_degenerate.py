#!/usr/bin/env python

"""
For one service:
- If a security group and/or role named "<env>-<service>" exists, remove it
- remove EC2 instance profiles as needed as well.

Copyright 2016-2020 Ellation, Inc.

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
import logging

import botocore
import click

import ef_conf_utils
import ef_service_registry
import ef_utils

logger = logging.getLogger()
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
logger.addHandler(ch)

logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)


def destroy_role(iam_client, role_name):
  """
  Destroy a role created by ef-generate. The role usually has the form env-service.
  """

  # Find the role and delete it, if it does not exist return
  try:
    role = iam_client.get_role(RoleName=role_name)
  except botocore.exceptions.ClientError as e:
    logger.info("Unable to find role %s: %s", role_name, e)
    return

  # Delete inline policies from the role
  policies = iam_client.list_role_policies(RoleName=role_name)
  for policy in policies['PolicyNames']:
    iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy)
    logger.info("Detached inline policy %s from role %s", policy, role_name)

  # Detach managed policies from the role
  policies = iam_client.list_attached_role_policies(RoleName=role_name)
  for policy in policies['AttachedPolicies']:
    iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
    logger.info("Detached managed policy %s from role %s", policy, role_name)

  # Finally we can delete the role
  try:
    iam_client.delete_role(RoleName=role['Role']['RoleName'])
    logger.info("Deleted role %s", role_name)
  except botocore.exceptions.ClientError as e:
    logger.info("Unable to delete role %s: %s", role_name, e)

  return

def destroy_instance_profile(iam_client, role_name):
  """
  Destroy instance profile created by ef-generate. Note we have to detach role first.
  """

  # First get the name of the instance profile
  try:
    instance_profile = iam_client.get_instance_profile(InstanceProfileName=role_name)
  except botocore.exceptions.ClientError as e:
    logger.info("Unable to delete instance profile %s: %s", role_name, e)
    return

  # Next we detach any roles associated with it
  for role in instance_profile['InstanceProfile']['Roles']:
    try:
      iam_client.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role['RoleName'])
    except botocore.exceptions.ClientError as e:
      logger.info("Unable to detach role %s from instance profile %s: %s", role['RoleName'], role_name, e)
      logger.info("Therefore we will not be able to delete instance profile %s", role_name)
      return

  # Now that we detached all roles, we can finally delete it
  try:
    iam_client.delete_instance_profile(InstanceProfileName=instance_profile['InstanceProfile']['InstanceProfileName'])
    logger.info("Deleted instance profile %s", role_name)
  except botocore.exceptions.ClientError as e:
    logger.info("Unable to delete instance profile %s: %s", role_name, e)

  return

def destroy_security_groups(ec2_client, role_name):
  """
  Destroy security groups created by ef-generate.
  """

  # First get the name of the security groups that start with the service name
  try:
    sgs = ec2_client.describe_security_groups(Filters=[{'Name':'group-name', 'Values': [role_name+"*"]}])
  except botocore.exceptions.ClientError as e:
    logger.info("Unable to find any security groups for %s: %s", role_name, e)
    return

  # Now we go through and delete each one
  for sg in sgs['SecurityGroups']:
    ec2_client.delete_security_group(GroupId=sg['GroupId'])
    logger.info("Deleted security group %s", sg['GroupName'])

  return

def destroy_kms_key(kms_client, target_name):
  """
  Schedule a key for deletion.
  Due to the KMS service workflow, the key will be deleted in a week.
  """
  target_name = target_name.replace('.', '_')
  key_alias = "alias/{}".format(target_name)
  try:
    key_data = kms_client.describe_key(KeyId=key_alias)["KeyMetadata"]
  except kms_client.exceptions.NotFoundException as e:
    logger.info("Did not find key %s", key_alias)
    return

  if key_data["KeyState"] == "PendingDeletion":
    logger.info("Key %s already scheduled for deletion on %s", key_alias, key_data["DeletionDate"])
    return

  key_id = key_data["KeyId"]
  try:
    deletion_info = kms_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    logger.info("Scheduled key %s deletion for %s", key_alias, deletion_info["DeletionDate"])
  except kms_client.exceptions.KMSInvalidStateException as e:
    logger.info("Key %s is in an invalid state: %s", key_alias, e)

def cloudformation_template_exists(cloudformation_client, target_name):
  """
  Check if the service CloudFormation template exits
  """
  # if the service contains a '.', this is a subservice
  #  the template exits only for the main service
  service_name = target_name.split('.')[0]

  try:
    cloudformation_client.describe_stacks(StackName=service_name)
  except botocore.exceptions.ClientError as e:
    if 'does not exist' in str(e):
      return False
    raise e

  logger.info("CloudFormation stack for service %s still exists", service_name)
  return True


@click.command()
@click.option("--service_name", "-s", required=True)
@click.option("--env", "-e", required=True)
@click.option("--ignore_cloudformation_template", default=False, is_flag=True)
@click.option('--sr',
              default=None,
              required=False,
              type=click.Path(exists=True, file_okay=True, dir_okay=False,
                              readable=True, resolve_path=True),
              help="path to service_registry.json")
def main(service_name, env, sr, ignore_cloudformation_template):
  profile = ef_conf_utils.get_account_alias(env)
  service_registry = ef_service_registry.EFServiceRegistry(sr)
  region = service_registry.service_region(service_name)
  clients = ef_utils.create_aws_clients(region, profile, "cloudformation", "ec2", "iam", "kms")
  target_name = "{}-{}".format(env, service_name)

  if cloudformation_template_exists(clients["cloudformation"], target_name):
    logger.error("CloudFormation still exists for service. Remove that and try again")
    if not ignore_cloudformation_template:
      exit(1)

  logger.info("Degenerating %s", target_name)
  destroy_instance_profile(clients["iam"], target_name)
  destroy_role(clients["iam"], target_name)
  destroy_security_groups(clients["ec2"], target_name)
  destroy_kms_key(clients["kms"], target_name)

if __name__ == "__main__":
  main()
