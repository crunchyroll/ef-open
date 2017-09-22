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
from StringIO import StringIO
import unittest

from botocore.exceptions import ClientError
from mock import Mock, patch

# For local application imports, context_paths must be first despite lexicon ordering
import context_paths
from ef_site_config import EFSiteConfig
import ef_utils


class TestEFUtils(unittest.TestCase):
  """
  Tests for 'ef_utils.py' Relies on the ef_site_config.py for testing. Look inside that file for where
  some of the test values are coming from.
  """
  @patch('sys.stderr', new_callable=StringIO)
  def test_fail_with_message(self, mock_stderr):
    """
    Tests fail() with a regular string message and checks if the message in stderr and exit code matches

    Args:
      mock_stderr: StringIO, captures the string sent to sys.stderr

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    with self.assertRaises(SystemExit) as exception:
      ef_utils.fail("Error Message")
    error_message = mock_stderr.getvalue().strip()
    self.assertEquals(error_message, "Error Message")
    self.assertEquals(exception.exception.code, 1)

  @patch('sys.stdout', new_callable=StringIO)
  @patch('sys.stderr', new_callable=StringIO)
  def test_fail_with_message_and_exception_data(self, mock_stderr, mock_stdout):
    """
    Test fail() with a regular string message and a python object as the exception data
    Args:
      mock_stderr: StringIO, captures the string sent to sys.stderr
      mock_stdout: StringIO, captures the string sent to sys.stdout

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    with self.assertRaises(SystemExit) as exception:
      ef_utils.fail("Error Message", {"ErrorCode": 22})
    error_message = mock_stderr.getvalue().strip()
    self.assertEquals(error_message, "Error Message")
    self.assertEquals(exception.exception.code, 1)
    output_message = mock_stdout.getvalue().strip()
    self.assertEquals(output_message, "{'ErrorCode': 22}")

  @patch('sys.stderr', new_callable=StringIO)
  def test_fail_with_None_message(self, mock_stderr):
    """
    Test fail() with a None object

    Args:
      mock_stderr: StringIO, captures the string sent to sys.stderr

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    with self.assertRaises(SystemExit) as exception:
      ef_utils.fail(None)
    error_message = mock_stderr.getvalue().strip()
    self.assertEquals(error_message, "None")
    self.assertEquals(exception.exception.code, 1)

  @patch('sys.stderr', new_callable=StringIO)
  def test_fail_with_empty_string(self, mock_stderr):
    """
    Test fail() with a an empty string

    Args:
      mock_stderr: StringIO, captures the string sent to sys.stderr

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    with self.assertRaises(SystemExit) as exception:
      ef_utils.fail("")
    error_message = mock_stderr.getvalue().strip()
    self.assertEquals(error_message, "")
    self.assertEquals(exception.exception.code, 1)

  @patch('urllib2.urlopen')
  def test_http_get_metadata_200_status_code(self, mock_urllib2):
    """
    Test http_get_metadata to retrieve an ami-id with 200 success status.

    Args:
      mock_urllib2: MagicMock, returns back 200 and the ami-id value

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_response = Mock(name="Always 200 Status Code")
    mock_response.getcode.return_value = 200
    mock_response.read.return_value = "ami-12345678"
    mock_urllib2.return_value = mock_response
    response = ef_utils.http_get_metadata("ami-id")
    self.assertEquals(response, "ami-12345678")

  @patch('urllib2.urlopen')
  def test_http_get_metadata_non_200_status_code(self, mock_urllib2):
    """
    Test http_get_metadata to retrieve ami-id and get a non 200 status code.

    Args:
      mock_urllib2:  MagicMock, returns back a non 200 status code.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_response = Mock(name="Always non-200 Status Code")
    mock_response.getcode.return_value = 400
    mock_urllib2.return_value = mock_response
    with self.assertRaises(IOError) as exception:
      ef_utils.http_get_metadata("ami-id")
    self.assertIn("Non-200 response", exception.exception.message)

  @patch('ef_utils.gethostname')
  def test_whereami_local(self, mock_gethostname):
    """
    Tests whereami to see if it returns 'local' by mocking a local machine environment

    Args:
      mock_gethostname: MagicMock, returns .local

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_gethostname.return_value = ".local"
    result = ef_utils.whereami()
    self.assertEquals(result, "local")

  @patch('ef_utils.gethostname')
  def test_whereami_unknown(self, mock_gethostname):
    """
    Tests whereami to see if it returns 'unknown' by mocking the environment to not match anything

    Args:
      mock_gethostname: MagicMock, returns some junk value

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_gethostname.return_value = "not local"
    result = ef_utils.whereami()
    self.assertEquals(result, "unknown")

  @patch('ef_utils.http_get_metadata')
  def test_http_get_instance_env(self, mock_http_get_metadata):
    """
    Tests http_get_instance_env to see if it returns 'dev' by mocking the metadata with a valid IAM instance profile

    Args:
      mock_http_get_metadata: MagicMock, returns a valid JSON InstanceProfileArn

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.return_value = "{\"InstanceProfileArn\": \"arn:aws:iam::1234:role/dev-server\"}"
    env = ef_utils.http_get_instance_env()
    self.assertEquals(env, "dev")

  @patch('ef_utils.http_get_metadata')
  def test_http_get_instance_env_exception(self, mock_http_get_metadata):
    """
    Tests http_get_instance_env to see if it raises an exception by mocking the metadata to be invalid

    Args:
      mock_http_get_metadata: MagicMock, returns junk value

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.return_value = "No data"
    with self.assertRaises(Exception) as exception:
      ef_utils.http_get_instance_env()
    self.assertIn("Error looking up metadata:iam/info", exception.exception.message)

  @patch('ef_utils.http_get_metadata')
  def test_http_get_instance_role(self, mock_http_get_metadata):
    """
    Tests http_get_instance_role to return the service name by mocking the metadata

    Args:
      mock_http_get_metadata: MagicMock, returns a valid JSON InstanceProfileArn

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.return_value = "{\"InstanceProfileArn\": \"arn:aws:iam::1234:role/dev-server\"}"
    role = ef_utils.http_get_instance_role()
    self.assertEquals(role, "server")

  @patch('ef_utils.http_get_metadata')
  def test_http_get_instance_role_exception(self, mock_http_get_metadata):
    """
    Tests http_get_instance_role to see if it raises an exception by giving it invalid metadata

    Args:
      mock_http_get_metadata: MagicMock, returns junk value

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.return_value = "No data"
    with self.assertRaises(Exception) as exception:
      ef_utils.http_get_instance_role()
    self.assertIn("Error looking up metadata:iam/info:", exception.exception.message)

  @patch('ef_utils.http_get_metadata')
  def test_get_instance_aws_context(self, mock_http_get_metadata):
    """
    Tests get_instance_aws_context to see if it produces a dict object with all the
    data supplied in the metadata.

    Args:
      mock_http_get_metadata: MagicMock, returns valid responses in the order its called

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.side_effect = ["us-west-2a", "i-00001111f"]
    mock_ec2_client = Mock(name="mock-ec2-client")
    mock_ec2_client.describe_instances.return_value = \
      {
        "Reservations": [
          {
            "OwnerId": "4444",
            "Instances": [
              {
                "IamInstanceProfile": {
                  "Arn": "arn:aws:iam::1234:instance-profile/dev0-server-ftp"
                }
              }
            ]
          }
        ]
      }
    result = ef_utils.get_instance_aws_context(mock_ec2_client)
    self.assertEquals(result["account"], "4444")
    self.assertEquals(result["env"], "dev0")
    self.assertEquals(result["env_short"], "dev")
    self.assertEquals(result["instance_id"], "i-00001111f")
    self.assertEquals(result["region"], "us-west-2")
    self.assertEquals(result["role"], "dev0-server-ftp")
    self.assertEquals(result["service"], "server-ftp")

  @patch('ef_utils.http_get_metadata')
  def test_get_instance_aws_context_metadata_exception(self, mock_http_get_metadata):
    """
    Tests get_instance_aws_context to see if it throws an exception by giving it invalid metadata

    Args:
      mock_http_get_metadata: MagicMock, throws an IOError exception

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.side_effect = IOError("No data")
    mock_ec2_client = Mock(name="mock-ec2-client")
    with self.assertRaises(IOError) as exception:
      ef_utils.get_instance_aws_context(mock_ec2_client)
    self.assertIn("Error looking up metadata:availability-zone or instance-id:", exception.exception.message)

  @patch('ef_utils.http_get_metadata')
  def test_get_instance_aws_context_ec2_invalid_environment_exception(self, mock_http_get_metadata):
    """
    Tests get_instance_aws_context to see if it throws an exception by modifying the describe_instances
    to return a IamInstanceProfile with an invalid environment in it.

    Args:
      mock_http_get_metadata: MagicMock, returns valid responses in the order its called

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.side_effect = ["us-west-2a", "i-00001111f"]
    mock_ec2_client = Mock(name="mock-ec2-client")
    mock_ec2_client.describe_instances.return_value = \
      {
        "Reservations": [
          {
            "OwnerId": "4444",
            "Instances": [
              {
                "IamInstanceProfile": {
                  "Arn": "arn:aws:iam::1234:instance-profile/invalid_env-server-ftp"
                }
              }
            ]
          }
        ]
      }
    with self.assertRaises(Exception) as exception:
      ef_utils.get_instance_aws_context(mock_ec2_client)
    self.assertIn("Did not find environment in role name:", exception.exception.message)

  @patch('subprocess.check_output')
  def test_pull_repo_ssh_credentials(self, mock_check_output):
    """
    Tests pull_repo by mocking the subprocess.check_output to return git ssh credentials.

    Args:
      mock_check_output: MagicMock, returns valid git responses in order of being called, with the
      repo coming from the ef_site_config.py

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_check_output.side_effect = [
      "user@" + EFSiteConfig.EF_REPO.replace("/", ":", 1) + ".git",
      EFSiteConfig.EF_REPO_BRANCH
    ]
    try:
      ef_utils.pull_repo()
    except RuntimeError as exception:
      self.fail("Exception occurred during test_pull_repo_ssh_credentials: " + exception.message)

  @patch('subprocess.check_output')
  def test_pull_repo_https_credentials(self, mock_check_output):
    """
    Tests the pull_repo by mocking the subprocess.check_output to return git http credentials.

    Args:
      mock_check_output: MagicMock, returns valid git responses in order of being called, with the
      repo coming from the ef_site_config.py

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_check_output.side_effect = [
      "origin\thttps://user@" + EFSiteConfig.EF_REPO + ".git",
      EFSiteConfig.EF_REPO_BRANCH
    ]
    try:
      ef_utils.pull_repo()
    except RuntimeError as exception:
      self.fail("Exception occurred during test_pull_repo_ssh_credentials: " + exception.message)

  @patch('subprocess.check_output')
  def test_pull_repo_incorrect_repo(self, mock_check_output):
    """
    Tests pull_repo to see if it throws an exception when the supplied repo doesn't match the one in
    ef_site_config.py

    Args:
      mock_check_output: MagicMock, returns git responses with non matching repo names

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_check_output.side_effect = [
      "user@github.com:company/wrong_repo.git "
      "other_user@github.com:company/wrong_repo.git"
    ]
    with self.assertRaises(RuntimeError) as exception:
      ef_utils.pull_repo()
    self.assertIn("Must be in", exception.exception.message)

  @patch('subprocess.check_output')
  def test_pull_repo_incorrect_branch(self, mock_check_output):
    """
    Tests pull_repo to see if it throws an error when the mocked check_output states it's on a branch
    other than the one specified in ef_site_config.py

    Args:
      mock_check_output: MagicMock, returns some valid git responses, with the
      repo coming from the ef_site_config.py, and then a non matching branch name

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_check_output.side_effect = [
      "user@" + EFSiteConfig.EF_REPO.replace("/", ":", 1) + ".git",
      "wrong_branch"
    ]
    with self.assertRaises(RuntimeError) as exception:
      ef_utils.pull_repo()
    self.assertIn("Must be on branch:", exception.exception.message)

  @patch('boto3.Session')
  def test_create_aws_clients(self, mock_session_constructor):
    """
    Tests create_aws_clients by providing all the parameters and mocking the boto3.Session constructor.
    Verifies that all the keys show up in the dict object returned.

    Args:
      mock_session_constructor: MagicMock, returns Mock object representing a boto3.Session object

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_session = Mock(name="mock-boto3-session")
    mock_session.client.return_value = Mock(name="mock-client")
    mock_session_constructor.return_value = mock_session
    amazon_services = ["acm", "batch", "ec2", "sqs"]
    client_dict = ef_utils.create_aws_clients("us-west-2d", "default", *amazon_services)
    self.assertTrue("acm" in client_dict)
    self.assertTrue("batch" in client_dict)
    self.assertTrue("ec2" in client_dict)
    self.assertTrue("sqs" in client_dict)
    self.assertTrue("SESSION" in client_dict)

  @patch('boto3.Session')
  def test_create_aws_clients_no_profile(self, mock_session_constructor):
    """
    Test create_aws_clients with all the parameters except profile and mocking the boto3 Session constructor.
    Verifies that all the keys show up in the dict object returned.

    Args:
      mock_session_constructor: MagicMock, returns Mock object representing a boto3.Session object

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_session = Mock(name="mock-boto3-session")
    mock_session.client.return_value = Mock(name="mock-client")
    mock_session_constructor.return_value = mock_session
    amazon_services = ["acm", "batch", "ec2", "sqs"]
    client_dict = ef_utils.create_aws_clients("us-west-2d", None, *amazon_services)
    self.assertTrue("acm" in client_dict)
    self.assertTrue("batch" in client_dict)
    self.assertTrue("ec2" in client_dict)
    self.assertTrue("sqs" in client_dict)
    self.assertTrue("SESSION" in client_dict)

  def test_get_account_alias(self):
    """
    Checks if get_account_alias returns the correct account based on valid environments

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    for env, account_alias in EFSiteConfig.ENV_ACCOUNT_MAP.items():
      # Attach a numeric value to environments that are ephemeral
      if env in EFSiteConfig.EPHEMERAL_ENVS:
        env += '0'
      self.assertEquals(ef_utils.get_account_alias(env), account_alias)

    # Do tests for global and mgmt envs, which have a special mapping, Example: global.account_alias
    if "global" in EFSiteConfig.ENV_ACCOUNT_MAP:
      for account_alias in EFSiteConfig.ENV_ACCOUNT_MAP.values():
        self.assertEquals(ef_utils.get_account_alias("global." + account_alias), account_alias)
    if "mgmt" in EFSiteConfig.ENV_ACCOUNT_MAP:
      for account_alias in EFSiteConfig.ENV_ACCOUNT_MAP.values():
        self.assertEquals(ef_utils.get_account_alias("mgmt." + account_alias), account_alias)

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
    for env, account_alias in EFSiteConfig.ENV_ACCOUNT_MAP.items():
      if env not in EFSiteConfig.EPHEMERAL_ENVS:
        env += '0'
      with self.assertRaises(ValueError) as exception:
        ef_utils.get_account_alias(env)
      self.assertTrue("unknown env" in exception.exception.message)

    # Hard coded junk values
    with self.assertRaises(ValueError) as exception:
      ef_utils.get_account_alias("non-existent-env")
    self.assertTrue("unknown env" in exception.exception.message)
    with patch('ef_utils.env_valid') as mock_env_valid:
      with self.assertRaises(ValueError) as exception:
        mock_env_valid.return_value = True
        ef_utils.get_account_alias("non-existent-env")
    self.assertTrue("has no entry in ENV_ACCOUNT_MAP" in exception.exception.message)
    with self.assertRaises(ValueError) as exception:
      ef_utils.get_account_alias("")
    self.assertTrue("unknown env" in exception.exception.message)
    with self.assertRaises(ValueError) as exception:
      ef_utils.get_account_alias(None)
    self.assertTrue("unknown env" in exception.exception.message)

  def test_get_env_short(self):
    """
    Checks if get_env_short returns the correct environment shortname when given valid environments

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    for env in EFSiteConfig.ENV_ACCOUNT_MAP:
      expected_env_value = env
      # Attach a numeric value to environments that are ephemeral
      if env in EFSiteConfig.EPHEMERAL_ENVS:
         env += '0'
      self.assertEquals(ef_utils.get_env_short(env), expected_env_value)

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
    for env in EFSiteConfig.ENV_ACCOUNT_MAP:
      if env not in EFSiteConfig.EPHEMERAL_ENVS:
        env += '0'
      with self.assertRaises(ValueError) as exception:
        ef_utils.get_env_short(env)
      self.assertTrue("unknown env" in exception.exception.message)

    # Hard coded junk values
    with self.assertRaises(ValueError) as exception:
      ef_utils.get_env_short("non-existent-env")
    self.assertTrue("unknown env" in exception.exception.message)
    with self.assertRaises(ValueError) as exception:
      ef_utils.get_env_short("")
    self.assertTrue("unknown env" in exception.exception.message)
    with self.assertRaises(ValueError) as exception:
      ef_utils.get_env_short(None)
    self.assertTrue("unknown env" in exception.exception.message)

  def test_env_valid(self):
    """
    Checks if env_valid returns true for correctly named environments

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    for env in EFSiteConfig.ENV_ACCOUNT_MAP:
      # Attach a numeric value to environments that are ephemeral
      if env in EFSiteConfig.EPHEMERAL_ENVS:
         env += '0'
      self.assertTrue(ef_utils.env_valid(env))

    # Do tests for global and mgmt envs, which have a special mapping, Example: global.account_alias
    if "global" in EFSiteConfig.ENV_ACCOUNT_MAP:
      for account_alias in EFSiteConfig.ENV_ACCOUNT_MAP.values():
        self.assertTrue(ef_utils.env_valid("global." + account_alias))
    if "mgmt" in EFSiteConfig.ENV_ACCOUNT_MAP:
      for account_alias in EFSiteConfig.ENV_ACCOUNT_MAP.values():
        self.assertTrue(ef_utils.env_valid("mgmt." + account_alias))

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
    for env in EFSiteConfig.ENV_ACCOUNT_MAP:
      if env not in EFSiteConfig.EPHEMERAL_ENVS:
        env += '0'
      with self.assertRaises(ValueError):
        ef_utils.env_valid(env)

    # Hard coded junk values
    with self.assertRaises(ValueError):
      ef_utils.env_valid("invalid_env")
    with self.assertRaises(ValueError):
      ef_utils.env_valid("")
    with self.assertRaises(ValueError):
      ef_utils.env_valid(None)

  def test_global_env_valid(self):
    """
    Checks global_env_valid returns true for account scoped envs.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    if "global" in EFSiteConfig.ENV_ACCOUNT_MAP:
      self.assertTrue(ef_utils.global_env_valid("global"))
    if "mgmt" in EFSiteConfig.ENV_ACCOUNT_MAP:
      self.assertTrue(ef_utils.global_env_valid("mgmt"))

  def test_global_env_valid_non_scoped_envs(self):
    """
    Checks global_env_valid returns false for non account scoped envs.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Loop through all environments that are not mgmt or global
    for env in EFSiteConfig.ENV_ACCOUNT_MAP:
      if env == "mgmt" or env == "global":
        continue
      with self.assertRaises(ValueError) as exception:
        ef_utils.global_env_valid(env)
      self.assertTrue("Invalid global env" in exception.exception.message)

    # Hard coded junk values
    with self.assertRaises(ValueError) as exception:
      ef_utils.global_env_valid("not_global")
    self.assertTrue("Invalid global env" in exception.exception.message)
    with self.assertRaises(ValueError) as exception:
      ef_utils.global_env_valid("not_mgmt")
    self.assertTrue("Invalid global env" in exception.exception.message)
    with self.assertRaises(ValueError) as exception:
      ef_utils.global_env_valid("")
    self.assertTrue("Invalid global env" in exception.exception.message)
    with self.assertRaises(ValueError) as exception:
      ef_utils.global_env_valid(None)
    self.assertTrue("Invalid global env" in exception.exception.message)


class TestEFUtilsKMS(unittest.TestCase):
  """Test cases for functions using kms"""

  def setUp(self):
    self.service = "test-service"
    self.env = "test"
    self.secret = "secret"
    self.error_response = {'Error': {'Code': 'FakeError', 'Message': 'Testing catch of all ClientErrors'}}
    self.client_error = ClientError(self.error_response, "boto3")
    self.mock_kms = Mock(name="mocked kms client")
    self.bytes_return = "cipher_blob".encode()
    self.mock_kms.encrypt.return_value = {"CiphertextBlob": self.bytes_return}
    self.mock_kms.decrypt.return_value = {"Plaintext": self.bytes_return}

  def test_kms_encrypt_call(self):
    """Validates basic kms call parameters"""
    ef_utils.kms_encrypt(self.mock_kms, self.service, self.env, self.secret)
    self.mock_kms.encrypt.assert_called_once_with(
      KeyId='alias/{}-{}'.format(self.env, self.service),
      Plaintext=self.secret.encode()
    )

  def test_kms_encrypt_call_subservice(self):
    """Validate KMS encryption call on a subservice, where periods should be converted to underscores due to
    alias name restrictions"""
    subservice = self.service + ".subservice"
    ef_utils.kms_encrypt(self.mock_kms, subservice, self.env, self.secret)
    self.mock_kms.encrypt.assert_called_once_with(
      KeyId='alias/{}-{}'.format(self.env, self.service + "_subservice"),
      Plaintext=self.secret.encode()
    )

  def test_kms_encrypt_returns_b64(self):
    """Validate that function returns a base64 encoded value"""
    encrypted_secret = ef_utils.kms_encrypt(self.mock_kms, self.service, self.env, self.secret)
    b64_return = base64.b64encode(self.bytes_return)
    self.assertEqual(b64_return, encrypted_secret)

  def test_kms_encrypt_fails_client_error(self):
    """Ensures that function fails a generic ClientError despite any special handling for specific error codes"""
    self.mock_kms.encrypt.side_effect = self.client_error
    with self.assertRaises(SystemExit):
      ef_utils.kms_encrypt(self.mock_kms, self.service, self.env, self.secret)

  def test_kms_decrypt_call(self):
    """Validates basic kms call parameters"""
    b64_secret = base64.b64encode(self.secret)
    ef_utils.kms_decrypt(self.mock_kms, b64_secret)
    self.mock_kms.decrypt.assert_called_once_with(CiphertextBlob=self.secret)

  def test_kms_decrypt_fails_without_b64_secret(self):
    """Ensures that function fails when passed a non-base64 encoded secret"""
    with self.assertRaises(SystemExit):
      ef_utils.kms_decrypt(self.mock_kms, self.secret)

  def test_kms_decrypt_fails_client_error(self):
    """Ensures that function fails a generic ClientError despite any special handling for specific error codes"""
    self.mock_kms.decrypt.side_effect = self.client_error
    with self.assertRaises(SystemExit):
      ef_utils.kms_decrypt(self.mock_kms, self.secret)


if __name__ == '__main__':
  unittest.main()
