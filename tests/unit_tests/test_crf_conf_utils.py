"""
Copyright 2016-2021 Ellation, Inc.
Copyright 2021-2022 Crunchyroll, Inc.

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

from crf_config import CRFConfig
import crf_conf_utils


class TestCRFConfUtils(unittest.TestCase):
  """
  Tests for 'crf_conf_utils.py' Relies on the crf_site_config.py for testing. Look inside that file for where
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
    test_parameters = crf_conf_utils.get_template_parameters_file(test_template)
    self.assertEquals(test_parameters, target_parameters)

  def test_global_env_valid(self):
    """
    Checks global_env_valid returns true for account scoped envs.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    if "global" in CRFConfig.ENV_ACCOUNT_MAP:
      self.assertTrue(crf_conf_utils.global_env_valid("global"))
    if "mgmt" in CRFConfig.ENV_ACCOUNT_MAP:
      self.assertTrue(crf_conf_utils.global_env_valid("mgmt"))

  def test_global_env_valid_non_scoped_envs(self):
    """
    Checks global_env_valid returns false for non account scoped envs.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Loop through all environments that are not mgmt or global
    for env in CRFConfig.ENV_ACCOUNT_MAP:
      if env == "mgmt" or env == "global":
        continue
      with self.assertRaises(ValueError) as exception:
        crf_conf_utils.global_env_valid(env)
      self.assertIn("Invalid global env", str(exception.exception))

    # Hard coded junk values
    with self.assertRaises(ValueError) as exception:
      crf_conf_utils.global_env_valid("not_global")
    self.assertIn("Invalid global env", str(exception.exception))
    with self.assertRaises(ValueError) as exception:
      crf_conf_utils.global_env_valid("not_mgmt")
    self.assertIn("Invalid global env", str(exception.exception))
    with self.assertRaises(ValueError) as exception:
      crf_conf_utils.global_env_valid("")
    self.assertIn("Invalid global env", str(exception.exception))
    with self.assertRaises(ValueError) as exception:
      crf_conf_utils.global_env_valid(None)
    self.assertIn("Invalid global env", str(exception.exception))

  def test_env_valid(self):
    """
    Checks if env_valid returns true for correctly named environments

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    for env in CRFConfig.ENV_ACCOUNT_MAP:
      # Attach a numeric value to environments that are ephemeral
      if env in CRFConfig.EPHEMERAL_ENVS:
         env += '0'
      self.assertTrue(crf_conf_utils.env_valid(env))

    # Do tests for global and mgmt envs, which have a special mapping, Example: global.account_alias
    if "global" in CRFConfig.ENV_ACCOUNT_MAP:
      for account_alias in CRFConfig.ENV_ACCOUNT_MAP.values():
        self.assertTrue(crf_conf_utils.env_valid("global." + account_alias))
    if "mgmt" in CRFConfig.ENV_ACCOUNT_MAP:
      for account_alias in CRFConfig.ENV_ACCOUNT_MAP.values():
        self.assertTrue(crf_conf_utils.env_valid("mgmt." + account_alias))

  def test_env_valid_invalid_envs(self):
    """
    Checks if env_valid returns ValueError for incorrectly name environments

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Create junk environment values by attaching numbers to non-ephemeral environments and not attaching numbers
    # to ephemeral environments
    for env in CRFConfig.ENV_ACCOUNT_MAP:
      if env not in CRFConfig.EPHEMERAL_ENVS:
        env += '0'
      with self.assertRaises(ValueError):
        crf_conf_utils.env_valid(env)

    # Hard coded junk values
    with self.assertRaises(ValueError):
      crf_conf_utils.env_valid("invalid_env")
    with self.assertRaises(ValueError):
      crf_conf_utils.env_valid("")
    with self.assertRaises(ValueError):
      crf_conf_utils.env_valid(None)

  def test_get_account_alias(self):
    """
    Checks if get_account_alias returns the correct account based on valid environments

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    for env, account_alias in CRFConfig.ENV_ACCOUNT_MAP.items():
      # Attach a numeric value to environments that are ephemeral
      if env in CRFConfig.EPHEMERAL_ENVS:
        env += '0'
      self.assertEquals(crf_conf_utils.get_account_alias(env), account_alias)

    # Do tests for global and mgmt envs, which have a special mapping, Example: global.account_alias
    if "global" in CRFConfig.ENV_ACCOUNT_MAP:
      for account_alias in CRFConfig.ENV_ACCOUNT_MAP.values():
        self.assertEquals(crf_conf_utils.get_account_alias("global." + account_alias), account_alias)
    if "mgmt" in CRFConfig.ENV_ACCOUNT_MAP:
      for account_alias in CRFConfig.ENV_ACCOUNT_MAP.values():
        self.assertEquals(crf_conf_utils.get_account_alias("mgmt." + account_alias), account_alias)

  def test_get_account_alias_invalid_env(self):
    """
    Tests if get_account_alias raises exceptions when given invalid environments

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Create junk environment values by attaching numbers to non-ephemeral environments and not attaching numbers
    # to ephemeral environments
    for env, account_alias in CRFConfig.ENV_ACCOUNT_MAP.items():
      if env not in CRFConfig.EPHEMERAL_ENVS:
        env += '0'
      with self.assertRaises(ValueError) as exception:
        crf_conf_utils.get_account_alias(env)
      self.assertIn("unknown env", str(exception.exception))

    # Hard coded junk values
    with self.assertRaises(ValueError) as exception:
      crf_conf_utils.get_account_alias("non-existent-env")
    self.assertIn("unknown env", str(exception.exception))
    with patch('crf_conf_utils.env_valid') as mock_env_valid:
      with self.assertRaises(ValueError) as exception:
        mock_env_valid.return_value = True
        crf_conf_utils.get_account_alias("non-existent-env")
    self.assertIn("has no entry in ENV_ACCOUNT_MAP", str(exception.exception))
    with self.assertRaises(ValueError) as exception:
      crf_conf_utils.get_account_alias("")
    self.assertIn("unknown env", str(exception.exception))
    with self.assertRaises(ValueError) as exception:
      crf_conf_utils.get_account_alias(None)
    self.assertIn("unknown env", str(exception.exception))

  def test_get_template_parameters_s3(self):
    """Test method returns valid parameters file"""
    mock_s3_resource = Mock(name="Mock S3 Client")
    response = {"Error": {"Code": "NoSuchKey"}}
    mock_s3_resource.Object.return_value.get.side_effect = [ClientError(response, "Get Object"), None]
    test_template = os.path.join('test-instance/templates/test.cnf')
    target_parameters = os.path.join('test-instance/parameters/test.cnf.parameters.yml')
    test_parameters = crf_conf_utils.get_template_parameters_s3(test_template, mock_s3_resource)
    self.assertEquals(test_parameters, target_parameters)

  def test_get_env_short(self):
    """
    Checks if get_env_short returns the correct environment shortname when given valid environments

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    for env in CRFConfig.ENV_ACCOUNT_MAP:
      expected_env_value = env
      # Attach a numeric value to environments that are ephemeral
      if env in CRFConfig.EPHEMERAL_ENVS:
         env += '0'
      self.assertEquals(crf_conf_utils.get_env_short(env), expected_env_value)

  def test_get_env_short_invalid_envs(self):
    """
    Tests if get_env_short raises exceptions when given invalid environments

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Create junk environment values by attaching numbers to non-ephemeral environments and not attaching numbers
    # to ephemeral environments
    for env in CRFConfig.ENV_ACCOUNT_MAP:
      if env not in CRFConfig.EPHEMERAL_ENVS:
        env += '0'
      with self.assertRaises(ValueError) as exception:
        crf_conf_utils.get_env_short(env)
      self.assertIn("unknown env", str(exception.exception))

    # Hard coded junk values
    with self.assertRaises(ValueError) as exception:
      crf_conf_utils.get_env_short("non-existent-env")
    self.assertIn("unknown env", str(exception.exception))
    with self.assertRaises(ValueError) as exception:
      crf_conf_utils.get_env_short("")
    self.assertIn("unknown env", str(exception.exception))
    with self.assertRaises(ValueError) as exception:
      crf_conf_utils.get_env_short(None)
    self.assertIn("unknown env", str(exception.exception))
