#!/usr/bin/env python

"""
For one service:
- If a security group and/or role named "<env>-<service>" exists, remove it
- remove EC2 instance profiles as needed as well.

If --commit flag is not set, only a dry run occurs; no changes are made.


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
import argparse
import json
import logging

import boto3
import botocore
import click

from pprint import pprint

logger = logging.getLogger()
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
# ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter('%(pathname)s:%(levelname)s - %(message)s'))
logger.addHandler(ch)

logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('boto3').setLevel(logging.CRITICAL)


def remove_and_destroy_role_instance_profiles(iam_client, role_name):
  """
  Removes and destroys all instance_profiles associated with the role
  """
  instance_profiles = iam_client.list_instance_profiles_for_role(RoleName=role_name).get("InstanceProfiles", [])
  pprint(instance_profiles)
  for profile in instance_profiles:
    profile_name = profile["InstanceProfileName"]
    logger.info("Removing instance profile %s from role %s", profile_name, role_name)



def destroy_role(iam_resource, role_name):
  """
  Destroy a role created by ef-generate. The role usually has the form env-service
  """
  try:
    role = iam_resource.Role(role_name)
  except botocore.exceptions.ClientError as e:
    logger.info("Could not find role %s", role_name)
    return
  instance_profiles = role.instance_profiles.all()
  pprint(instance_profiles)
  for profile in instance_profiles:
    logger.info("Removing instance role %s from instance_profile %s", role_name, profile.instance_profile_name)
    profile.remove_role(RoleName=role.role_name)
    logger.info("Deleting instance role %s", profile.arn)
    profile.delete()


  for attached_policy in role.attached_policies.all():
    logger.info("Detaching policy %s from role %s", attached_policy.policy_name, role_name)
    role.detach_policy(PolicyArn=attached_policy.arn)

  print(list(role.policies.all()))
  for policy in role.policies.all():
    logger.info("Deleting inline policy %s from role %s", policy.policy_name, role_name)
    policy.delete()

  logger.info("Deleting role {}".format(role_name))

  role.delete()





@click.command()
@click.option("--service_name", "-s", required=True)
@click.option("--env", "-e", required=True)
def main(service_name, env):
  session = boto3.Session()
  iam_client = session.resource("iam")

  # help(iam_client)
  target_name = "{}-{}".format(env, service_name)
  logger.info("Degenerating {}".format(target_name))
  destroy_role(iam_client, target_name)


if __name__ == "__main__":
  main()
