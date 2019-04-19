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

import base64
import os
from StringIO import StringIO
import unittest

from botocore.exceptions import ClientError
from mock import Mock, patch

# For local application imports, context_paths must be first despite lexicon ordering
import context_paths

from ef_config import EFConfig
import ef_conf_utils


class TestEFConfUtils(unittest.TestCase):
  """
  Tests for 'ef_conf_utils.py' Relies on the ef_site_config.py for testing. Look inside that file for where
  some of the test values are coming from.
  """

  def setUp(self):
    """
    Setup function that is run before every test

    Returns:
      None
    """
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))

  def test_get_template_parameters_file(self):
    """Test method returns valid parameters file"""
    test_template = os.path.join(os.path.dirname(__file__), '../test_data/templates/test.cnf')
    target_parameters = os.path.join(os.path.dirname(__file__), '../test_data/parameters/test.cnf.parameters.yml')
    test_parameters = ef_conf_utils.get_template_parameters_file(test_template)
    self.assertEquals(test_parameters, target_parameters)

  def test_global_env_valid(self):
    """
    Checks global_env_valid returns true for account scoped envs.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    if "global" in EFConfig.ENV_ACCOUNT_MAP:
      self.assertTrue(ef_conf_utils.global_env_valid("global"))
    if "mgmt" in EFConfig.ENV_ACCOUNT_MAP:
      self.assertTrue(ef_conf_utils.global_env_valid("mgmt"))

  def test_global_env_valid_non_scoped_envs(self):
    """
    Checks global_env_valid returns false for non account scoped envs.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Loop through all environments that are not mgmt or global
    for env in EFConfig.ENV_ACCOUNT_MAP:
      if env == "mgmt" or env == "global":
        continue
      with self.assertRaises(ValueError) as exception:
        ef_conf_utils.global_env_valid(env)
      self.assertTrue("Invalid global env" in exception.exception.message)

    # Hard coded junk values
    with self.assertRaises(ValueError) as exception:
      ef_conf_utils.global_env_valid("not_global")
    self.assertTrue("Invalid global env" in exception.exception.message)
    with self.assertRaises(ValueError) as exception:
      ef_conf_utils.global_env_valid("not_mgmt")
    self.assertTrue("Invalid global env" in exception.exception.message)
    with self.assertRaises(ValueError) as exception:
      ef_conf_utils.global_env_valid("")
    self.assertTrue("Invalid global env" in exception.exception.message)
    with self.assertRaises(ValueError) as exception:
      ef_conf_utils.global_env_valid(None)
    self.assertTrue("Invalid global env" in exception.exception.message)
