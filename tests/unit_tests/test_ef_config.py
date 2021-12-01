"""
Copyright 2016-2017 Crunchyroll, Inc.

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

from mock import Mock, patch

import context_paths
from crf_config import CRFConfig


class TestCRFConfig(unittest.TestCase):
  """
  TestCRFConfig class for crf_config testing.
  """

  def test_env_account_map(self):
    """Test env account map returns correct account alias"""
    self.assertEqual(CRFConfig.ENV_ACCOUNT_MAP["test"], "testaccount")

  def test_env_account_map_missing_env(self):
    """Test account map does not return account alias for non-existant env"""
    with self.assertRaises(KeyError):
      CRFConfig.ENV_ACCOUNT_MAP["notanenv"]

  def test_service_groups(self):
    """Test service groups contains correct service group"""
    self.assertIn("application_services", CRFConfig.SERVICE_GROUPS)

  def test_service_groups_has_fixtures(self):
    """Test service groups contains 'fixtures' service group"""
    self.assertIn("fixtures", CRFConfig.SERVICE_GROUPS)

  def test_service_groups_missing_group(self):
    """Test services groups does not contain non-existant service group"""
    self.assertNotIn("not_a_service_group", CRFConfig.SERVICE_GROUPS)

  def test_account_alias_list_type_set(self):
    """Test account alias list is of type 'set'"""
    print("Im a good string")
    print(type(CRFConfig.ACCOUNT_ALIAS_LIST))
    self.assertIs(type(CRFConfig.ACCOUNT_ALIAS_LIST), set)

  def test_account_alias_list_values(self):
    """Test account alias list contains correct account alias"""
    self.assertIn("testaccount", CRFConfig.ACCOUNT_ALIAS_LIST)

  def test_account_alias_list_missing_group(self):
    """Test account alias list does not contain non-existant account alias"""
    self.assertNotIn("notanaccountalias", CRFConfig.ACCOUNT_ALIAS_LIST)

  def test_env_list_includes_ephemeral(self):
    """Test env list contains the correct number of ephemeral envs"""
    self.assertIn("alpha0", CRFConfig.ENV_LIST)
    self.assertIn("alpha1", CRFConfig.ENV_LIST)
    self.assertIn("alpha2", CRFConfig.ENV_LIST)
    self.assertIn("alpha3", CRFConfig.ENV_LIST)
    self.assertNotIn("alpha4", CRFConfig.ENV_LIST)

  def test_env_list_includes_non_ephemeral(self):
    """Test env list contains correctly named non-ephemeral environment """
    self.assertIn("test", CRFConfig.ENV_LIST)

  def test_env_list_includes_no_ephemeral(self):
    """Test env list contains correctly named non-ephemeral environment """
    self.assertNotIn("test0", CRFConfig.ENV_LIST)

  def test_env_list_includes_global(self):
    """Test env account map returns correct account alias"""
    self.assertIn("global.testaccount", CRFConfig.ENV_LIST)

  def test_env_list_includes_mgmt(self):
    """Test env account map returns correct account alias"""
    self.assertIn("mgmt.testaccount", CRFConfig.ENV_LIST)
