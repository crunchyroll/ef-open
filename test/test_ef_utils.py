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

from StringIO import StringIO
import unittest

from mock import patch

import context
from src.ef_utils import fail
from src.ef_utils import env_valid, get_account_alias, get_env_short


class TestEFUtils(unittest.TestCase):
  """
  Tests for 'ef_utils.py' Relies on the ef_site_config.py for testing. Look inside that file for where
  some of the test values are coming from.
  """
  @patch('sys.stderr', new_callable=StringIO)
  def test_fail_with_message(self, mock_stderr):
    """
    Tests fail() with a regular string message and checks if the message in stderr and exit code matches
    :param mock_stderr: StringIO
    :return: None
    """
    with self.assertRaises(SystemExit) as exception:
      fail("Error Message")
    error_message = mock_stderr.getvalue().strip()
    self.assertEquals(error_message, 'Error Message')
    self.assertEquals(exception.exception.code, 1)

  @patch('sys.stdout', new_callable=StringIO)
  @patch('sys.stderr', new_callable=StringIO)
  def test_fail_with_message_and_exception_data(self, mock_stderr, mock_stdout):
    """
    Test fail() with a regular string message and a python object as the exception data
    :param mock_stderr: StringIO
    :param mock_stdout: StringIO
    :return: None
    """
    with self.assertRaises(SystemExit) as exception:
      fail("Error Message", {"ErrorCode": 22})
    error_message = mock_stderr.getvalue().strip()
    self.assertEquals(error_message, 'Error Message')
    self.assertEquals(exception.exception.code, 1)
    output_message = mock_stdout.getvalue().strip()
    self.assertEquals(output_message, "{'ErrorCode': 22}")

  @patch('sys.stderr', new_callable=StringIO)
  def test_fail_with_None_message(self, mock_stderr):
    """
    Test fail() with a None object
    :param mock_stderr: StringIO
    :return: None
    """
    with self.assertRaises(SystemExit) as exception:
      fail(None)
    error_message = mock_stderr.getvalue().strip()
    self.assertEquals(error_message, 'None')
    self.assertEquals(exception.exception.code, 1)

  def test_env_valid_with_valid_envs(self):
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

    assert env_valid("test") == True

  def test_env_valid_with_invalid_envs(self):
    """
    Checks if env_valid returns ValueError for incorrectly name environments
    :return: None
    """
    with self.assertRaises(ValueError):
      env_valid("test0")
    with self.assertRaises(ValueError):
      env_valid("dev")
    with self.assertRaises(ValueError):
      env_valid("staging")
    with self.assertRaises(ValueError):
      env_valid("prod0")
    with self.assertRaises(ValueError):
      env_valid("no_env")

  def test_get_account_alias_with_valid_envs(self):
    """
    Checks if get_account_alias returns the correct account alias based on valid environments specified
    :return:
    """
    self.assertEquals(get_account_alias("test"), "test")
    self.assertEquals(get_account_alias("dev0"), "dev")
    self.assertEquals(get_account_alias("dev1"), "dev")
    self.assertEquals(get_account_alias("dev2"), "dev")
    self.assertEquals(get_account_alias("staging0"), "staging")
    self.assertEquals(get_account_alias("prod"), "prod")

    assert get_account_alias("dev0") == "dev"

  def test_get_env_short_with_valid_envs(self):
    """
    Checks if get_env_short returns the correct environment shortname based on valid environments specified
    :return:
    """
    self.assertEquals(get_env_short("test"), "test")
    self.assertEquals(get_env_short("dev0"), "dev")
    self.assertEquals(get_env_short("dev1"), "dev")
    self.assertEquals(get_env_short("dev2"), "dev")
    self.assertEquals(get_env_short("staging0"), "staging")
    self.assertEquals(get_env_short("prod"), "prod")


if __name__ == '__main__':
   unittest.main()
