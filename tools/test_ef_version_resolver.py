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

import unittest

import boto3

from ef_version_resolver import EFVersionResolver
from ef_config import EFConfig
from ef_utils import fail, get_account_alias, http_get_metadata, whereami

class TestEFVersionResolver(unittest.TestCase):
  """Tests for 'ef_version_resolver.py'"""

  # initialize based on where running
  where = whereami()
  if where == "local":
    session = boto3.Session(profile_name=get_account_alias("proto0"), region_name=EFConfig.DEFAULT_REGION)
  elif where == "ec2":
    region = http_get_metadata("placement/availability-zone/")
    region = region[:-1]
    session = boto3.Session(region_name=region)
  else:
    fail("Can't test in environment: " + where)

  clients = {
    "ec2": session.client("ec2")
  }

  def test_ami_id(self):
    """Does ami-id,data-api resolve to an AMI id"""
    test_string = "ami-id,data-api"
    resolver = EFVersionResolver(TestEFVersionResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^ami-[a-f0-9]{8}$")


if __name__ == '__main__':
  unittest.main()
