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

import unittest

from src.ef_utils import env_valid, get_account_alias, get_env_short


class TestEFUtils(unittest.TestCase):
  """
  Tests for 'ef_utils.py' Relies on the ef_site_config.py for testing. Look inside that file for where
  some of the test values are coming from.
  """

  def test_env_valid(self):
    """
    Checks if env_valid returns true for correctly named named environments
    :return: None
    """
    self.assertTrue(env_valid("test"))
    self.assertTrue(env_valid("dev0"))
    self.assertTrue(env_valid("dev1"))
    self.assertTrue(env_valid("dev2"))
    self.assertTrue(env_valid("staging0"))
    self.assertTrue(env_valid("prod"))

  def test_env_valid_with_invalid_envs(self):
    """
    Checks if env_valid returns ValueError for incorrectly name environments
    :return: None
    """
    self.assertRaises(ValueError, env_valid, "test0")
    self.assertRaises(ValueError, env_valid, "dev")
    self.assertRaises(ValueError, env_valid, "staging")
    self.assertRaises(ValueError, env_valid, "prod0")
    self.assertRaises(ValueError, env_valid, "no_env")

  def test_get_account_alias(self):
    """Does get_account_alias resolve correctly"""
    self.assertEquals(get_account_alias("prod"), "ellation")
    self.assertEquals(get_account_alias("staging"), "ellationeng")
    self.assertEquals(get_account_alias("proto0"), "ellationeng")
    self.assertEquals(get_account_alias("global.ellation"), "ellation")

  def test_get_env_short(self):
    """Does get_env_short resolve correctly"""
    self.assertEquals(get_env_short("prod"), "prod")
    self.assertEquals(get_env_short("staging"), "staging")
    self.assertEquals(get_env_short("proto0"), "proto")
    self.assertEquals(get_env_short("global.ellation"), "global")


if __name__ == '__main__':
  unittest.main()
