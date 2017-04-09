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

#from ef_utils import env_valid, get_account_alias, get_env_short
from ef_utils import env_valid, get_account_alias, get_env_short

class TestEFUtils(unittest.TestCase):
  """Tests for 'ef_utils.py'"""

  def test_env_valid(self):
    """Does valid_env resolve correctly"""
    self.assertTrue(env_valid("prod"))
    self.assertTrue(env_valid("staging"))
    self.assertTrue(env_valid("proto0"))
    self.assertTrue(env_valid("global.ellation"))

  def test_env_invalid(self):
    """Does valid_env raise ValueError"""
    self.assertRaises(ValueError, env_valid, "proto")
    self.assertRaises(ValueError, env_valid, "global")
    self.assertRaises(ValueError, env_valid, "global.notanalias")
    self.assertRaises(ValueError, env_valid, "notanenv")

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
