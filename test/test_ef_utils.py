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
import urllib2

from mock import MagicMock, Mock, patch

# For local application imports, context must be first despite lexicon ordering
import context
from src.ef_utils import fail
from src.ef_utils import env_valid, get_account_alias, get_env_short
from src.ef_utils import http_get_metadata, whereami, http_get_instance_env, http_get_instance_role


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

  @patch('urllib2.urlopen')
  def test_http_get_metadata_200_status_code(self, mock_urllib2):
    """
    Test http_get_metadata with mock urllib2.urlopen call that returns 200 and ami ID
    :param mock_urllib2: MagicMock
    :return: None
    """
    mock_response = Mock(name="Always 200 Status Code")
    mock_response.getcode.return_value = 200
    mock_response.read.return_value = "ami-12345678"
    mock_urllib2.return_value = mock_response
    response = http_get_metadata("ami-id")
    self.assertEquals(response, "ami-12345678")

  @patch('urllib2.urlopen')
  def test_http_get_metadata_non_200_status_code(self, mock_urllib2):
    """
    Test http_get_metadata with mock urllib2.urlopen call that returns 400.
    :param mock_urllib2: MagicMock
    :return: None
    """
    mock_response = Mock(name="Always non-200 Status Code")
    mock_response.getcode.return_value = 400
    mock_urllib2.return_value = mock_response
    with self.assertRaises(IOError) as exception:
      http_get_metadata("ami-id")
    self.assertTrue("400" in exception.exception.message)
    self.assertTrue("ami-id" in exception.exception.message)

  @patch('urllib2.urlopen')
  def test_http_get_metadata_urllib2_URLError(self, mock_urllib2):
    """
    Test http_get_metadata with mock urllib2.urlopen that raises a URLError exception
    :param mock_urllib2: MagicMock
    :return: None
    """
    mock_urllib2.side_effect = urllib2.URLError("Mock URLError")
    with self.assertRaises(IOError) as exception:
      http_get_metadata("ami-id")
    self.assertTrue("Mock URLError" in exception.exception.message)

  @unittest.skipIf(whereami() == "ec2", "Test is running in ec2 environment, will not fail so must skip.")
  def test_http_get_metadata_urllib2_default_timeout(self):
    with self.assertRaises(IOError) as exception:
      http_get_metadata("ami-id")
    self.assertTrue("timed out" in exception.exception.message)

  @unittest.skipIf(whereami() == "ec2", "Test is running in ec2 environment, will not fail so must skip.")
  def test_http_get_metadata_urllib2_1_second_timeout(self):
    with self.assertRaises(IOError) as exception:
      http_get_metadata("ami-id", 1)
    self.assertTrue("timed out" in exception.exception.message)

  @patch('src.ef_utils.http_get_metadata')
  def test_whereami_ec2(self, mock_http_get_metadata):
    mock_http_get_metadata.return_value = "i-123456"
    result = whereami()
    self.assertEquals(result, "ec2")

  @patch('subprocess.check_output')
  @patch('src.ef_utils.access')
  @patch('src.ef_utils.isfile')
  @patch('src.ef_utils.http_get_metadata')
  def test_whereami_virtualbox(self, mock_http_get_metadata, mock_isfile, mock_access, mock_check_output):
    mock_http_get_metadata.return_value = "not ec2"
    mock_isfile.return_value = True
    mock_access.return_value = True
    mock_check_output.return_value = "virtualbox\nkvm\nother\n"
    result = whereami()
    self.assertEquals(result, "virtualbox-kvm")

  @patch('src.ef_utils.gethostname')
  def test_whereami_local(self, mock_gethostname):
    mock_gethostname.return_value = ".local"
    result = whereami()
    self.assertEquals(result, "local")

  @patch('src.ef_utils.gethostname')
  def test_whereami_unknown(self, mock_gethostname):
    mock_gethostname.return_value = "not local"
    result = whereami()
    self.assertEquals(result, "unknown")

  @patch('src.ef_utils.http_get_metadata')
  def test_http_get_instance_env(self, mock_http_get_metadata):
    mock_http_get_metadata.return_value = "{\"InstanceProfileArn\": \"arn:aws:iam::1234:instance-profile/dev-server\"}"
    env = http_get_instance_env()
    self.assertEquals(env, "dev")

  @patch('src.ef_utils.http_get_metadata')
  def test_http_get_instance_env_exception(self, mock_http_get_metadata):
    mock_http_get_metadata.return_value = "No data"
    with self.assertRaises(Exception) as exception:
      http_get_instance_env()

  @patch('src.ef_utils.http_get_metadata')
  def test_http_get_instance_role(self, mock_http_get_metadata):
    mock_http_get_metadata.return_value = "{\"InstanceProfileArn\": \"arn:aws:iam::1234:instance-profile/dev-server\"}"
    role = http_get_instance_role()
    self.assertEquals(role, "server")

  @patch('src.ef_utils.http_get_metadata')
  def test_http_get_instance_role_exception(self, mock_http_get_metadata):
    mock_http_get_metadata.return_value = "No data"
    with self.assertRaises(Exception) as exception:
      http_get_instance_role()

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
