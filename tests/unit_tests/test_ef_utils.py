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
import ef_utils


class TestEFUtils(unittest.TestCase):
  """
  Tests for 'ef_utils.py' Relies on the ef_site_config.py for testing. Look inside that file for where
  some of the test values are coming from.
  """

  def setUp(self):
    """
    Setup function that is run before every test

    Returns:
      None
    """
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))

  def tearDown(self):
    """
    Teardown function that is run after every test.

    Returns:
      None
    """
    pass

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
    self.assertIn("Non-200 response", str(exception.exception))

  @patch('ef_utils.getenv')
  @patch('ef_utils.http_get_metadata')
  def test_whereami_ec2(self, mock_http_get_metadata, getenv):
    """
    Tests whereami to see if it returns 'ec2' by mocking an ec2 environment

    Args:
      mock_http_get_metadata: MagicMock, returns "i-somestuff"

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.return_value = "i-somestuff"
    getenv.return_value = False
    result = ef_utils.whereami()
    self.assertEquals(result, "ec2")

  @patch('ef_utils.getenv')
  @patch('ef_utils.http_get_metadata')
  def test_whereami_jenkins(self, mock_http_get_metadata, mock_getenv):
    """
    Tests whereami to see if it returns 'jenkins' by mocking an ec2 Jenkins
    environment

    Args:
      mock_http_get_metadata: MagicMock, returns "i-somestuff"
      mock_get_env: MagicMock, mocks the environment variables

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.return_value = "i-somestuff"

    def getenv_side_effect(key, default=None):
      if key == "JENKINS_URL":
        return True
      if key == "JENKINS_DOCKER":
        return None
      return default
    mock_getenv.side_effect = getenv_side_effect
    result = ef_utils.whereami()
    self.assertEquals(result, "jenkins")

  @patch('ef_utils.getenv')
  @patch('ef_utils.http_get_metadata')
  def test_whereami_jenkins_docker(self, mock_http_get_metadata, mock_getenv):
    """
    Tests whereami to see if it returns 'ec2' by mocking an ec2 Jenkins Docker
    environment

    Args:
      mock_http_get_metadata: MagicMock, returns "i-somestuff"
      mock_get_env: MagicMock, mocks the environment variables

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.return_value = "i-somestuff"
    def getenv_side_effect(key, default=None):
      if key == "JENKINS_URL":
        return True
      if key == "JENKINS_DOCKER":
        return True
      return default
    mock_getenv.side_effect = getenv_side_effect
    result = ef_utils.whereami()
    self.assertEquals(result, "ec2")

  @patch('ef_utils.getenv')
  @patch('ef_utils.is_in_virtualbox')
  @patch('ef_utils.gethostname')
  @patch('ef_utils.http_get_metadata')
  def test_whereami_local(self, mock_http_get_metadata, mock_gethostname, mock_is_in_virtualbox, mock_getenv):
    """
    Tests whereami to see if it returns 'local' by mocking a local machine environment

    Args:
      mock_http_get_metadata: MagicMock, returns something other than "i-...."
      mock_gethostname: MagicMock, returns .local

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_getenv.return_value = False
    mock_http_get_metadata.return_value = "nothinguseful"
    mock_is_in_virtualbox.return_value = False
    mock_gethostname.return_value = ".local"
    result = ef_utils.whereami()
    self.assertEquals(result, "local")

  @patch('ef_utils.getenv')
  @patch('ef_utils.is_in_virtualbox')
  @patch('ef_utils.gethostname')
  @patch('ef_utils.http_get_metadata')
  def test_whereami_unknown(self, mock_http_get_metadata, mock_gethostname, mock_is_in_virtualbox, mock_getenv):
    """
    Tests whereami to see if it returns 'unknown' by mocking the environment to not match anything

    Args:
      mock_http_get_metadata: MagicMock, returns something other than "i-...."
      mock_gethostname: MagicMock, returns some junk value

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_getenv.return_value = False
    mock_http_get_metadata.return_value = "nothinguseful"
    mock_is_in_virtualbox.return_value = False
    mock_gethostname.return_value = "not local"
    result = ef_utils.whereami()
    self.assertEquals(result, "unknown")

  @patch('ef_utils.http_get_metadata')
  def test_http_get_instance_env(self, mock_http_get_metadata):
    """
    Tests http_get_instance_env to see if it returns 'alpha' by mocking the metadata with a valid IAM instance profile

    Args:
      mock_http_get_metadata: MagicMock, returns a valid JSON InstanceProfileArn

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_http_get_metadata.return_value = "{\"InstanceProfileArn\": \"arn:aws:iam::1234:role/alpha-server\"}"
    env = ef_utils.http_get_instance_env()
    self.assertEquals(env, "alpha")

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
    self.assertIn("Error looking up metadata:iam/info", str(exception.exception))

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
    mock_http_get_metadata.return_value = "{\"InstanceProfileArn\": \"arn:aws:iam::1234:role/alpha-server\"}"
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
    self.assertIn("Error looking up metadata:iam/info:", str(exception.exception))

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

  @patch('boto3.Session')
  def test_create_aws_clients_cache_multiple_configs(self, mock_session_constructor):
    """
    Test create_aws_clients with multiple parameters and mocking the boto3
    Session constructor.

    Check that every (region, profile) pair gets its own set of clients.

    Args:
      mock_session_constructor: MagicMock, returns Mock object representing a boto3.Session object

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_session = Mock(name="mock-boto3-session")
    # make sure we get different clients on every call
    mock_session.client.side_effect = lambda *args, **kwargs: Mock(name="mock-boto3-session")
    mock_session_constructor.return_value = mock_session
    amazon_services = ["acm", "batch", "ec2", "sqs"]

    cases = [
        ("us-west-2d", None),
        ("us-west-3d", None),
        ("us-west-2d", "codemobs"),
        ("us-west-2d", "ellationeng"),
        ("", None),
    ]

    built_clients = {}

    for region, profile in cases:
      client_dict = ef_utils.create_aws_clients(region, profile, *amazon_services)

      for key, clients in built_clients.items():
        # check if the new clients are unique
        self.assertNotEquals(client_dict, clients,
                             msg="Duplicate clients for {} vs {}".format(key, (region, profile)))
      built_clients[(region, profile)] = client_dict

  @patch('boto3.Session')
  def test_create_aws_clients_cache_same_client(self, mock_session_constructor):
    """
    Test create_aws_clients with same parameters and mocking the boto3
    Session constructor.

    Check that we get the same clients every time.

    Args:
      mock_session_constructor: MagicMock, returns Mock object representing a boto3.Session object

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_session = Mock(name="mock-boto3-session")
    # make sure we get different clients on every call
    mock_session.client.side_effect = lambda *args, **kwargs: Mock(name="mock-boto3-session")
    mock_session_constructor.return_value = mock_session
    amazon_services = ["acm", "batch", "ec2", "sqs"]
    cases = [
        ("us-west-2d", None),
        ("us-west-3d", None),
        ("us-west-2d", "codemobs"),
        ("us-west-2d", "ellationeng"),
        ("", None),
    ]
    for region, profile in cases:
      clients1 = ef_utils.create_aws_clients(region, profile, *amazon_services)
      clients2 = ef_utils.create_aws_clients(region, profile, *amazon_services)

      self.assertEquals(clients1, clients2, msg="Should get the same clients for the same region/profile pair")

  @patch('boto3.Session')
  def test_create_aws_clients_cache_new_clients(self, mock_session_constructor):
    """
    Test create_aws_clients with same parameters and mocking the boto3
    Session constructor.

    Check that we get the same clients every time.

    Args:
      mock_session_constructor: MagicMock, returns Mock object representing a boto3.Session object

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_session = Mock(name="mock-boto3-session")
    # make sure we get different clients on every call
    mock_session.client.side_effect = lambda *args, **kwargs: Mock(name="mock-boto3-session")
    mock_session_constructor.return_value = mock_session
    amazon_services = ["acm", "batch", "ec2", "sqs"]
    new_amazon_services = amazon_services + ["cloudfront"]
    region, profile = "us-west-2", "testing"

    clients = ef_utils.create_aws_clients(region, profile, *amazon_services)
    # copy the old clients, so they're not overwritten
    built_clients = {k: v for k, v in clients.items()}
    new_clients = ef_utils.create_aws_clients(region, profile, *new_amazon_services)

    for service in new_amazon_services:
      self.assertIn(service, new_clients)

    for service, client in built_clients.items():
      self.assertEquals(new_clients.get(service), client)

  @patch('boto3.Session')
  def test_create_aws_clients_cache_posoning(self, mock_session_constructor):
    """
    Test that create_aws_clients does not allow cache poisoning by returning a
    different dict at the same time.

    Check that we get the same clients every time.

    Args:
      mock_session_constructor: MagicMock, returns Mock object representing a boto3.Session object

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_session = Mock(name="mock-boto3-session")
    # make sure we get different clients on every call
    mock_session.client.side_effect = lambda *args, **kwargs: Mock(name="mock-boto3-session")
    mock_session_constructor.return_value = mock_session
    amazon_services = ["acm", "batch", "ec2", "sqs"]
    new_amazon_services = amazon_services + ["cloudfront"]
    region, profile = "us-west-2", "testing"

    clients = ef_utils.create_aws_clients(region, profile, *amazon_services)

    clients.update([('not-a-service', 'not-a-client')])

    new_clients = ef_utils.create_aws_clients(region, profile, *amazon_services)

    test_service = amazon_services[0]

    self.assertIs(clients[test_service], new_clients[test_service], "Old clients should be the same in both dicts, as they are cached")
    self.assertIsNot(clients, new_clients, "New client dicts should not be the same object as old client dicts, even though the clients are the same")
    self.assertNotEqual(clients, new_clients, "New clients should not be affected by the update")


  def test_get_account_id(self):
    """
    Checks if get_account_id returns the correct account id

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_account_id = "123456789"
    mock_sts_client = Mock(name="mock sts client")
    mock_sts_client.get_caller_identity.return_value.get.return_value = target_account_id
    self.assertEquals(ef_utils.get_account_id(mock_sts_client), target_account_id)


  def test_get_autoscaling_group_properties_valid_asg_name(self):
    """Test method returns valid parameters file"""
    mock_asg_resource = Mock(name="Mock Autoscaling Client")
    mock_asg_resource.describe_auto_scaling_groups.return_value = \
    {
      "AutoScalingGroups": [
        {
          "DesiredCapacity": 2,
          "Tags": [
            {
              "ResourceType": "auto-scaling-group",
              "ResourceId": "alpha0-test-instance-ServerGroup",
              "PropagateAtLaunch": "true",
              "Value": "alpha0-test-instance",
              "Key": "Name"
            }
          ],
          "AutoScalingGroupName": "alpha0-test-instance-ServerGroup"
        }
      ]
    }
    result = ef_utils.get_autoscaling_group_properties(mock_asg_resource, "alpha0", "test-instance")
    self.assertEquals(result[0]["DesiredCapacity"], 2)
    self.assertEquals(result[0]["AutoScalingGroupName"], "alpha0-test-instance-ServerGroup")
    self.assertEquals(result[0]["Tags"][0]["ResourceId"], "alpha0-test-instance-ServerGroup")

  def test_get_autoscaling_group_properties_valid_tag_name(self):
    """Test method returns valid parameters file"""
    mock_asg_resource = Mock(name="Mock Autoscaling Client")
    mock_asg_resource.describe_auto_scaling_groups.return_value = \
    {
      "AutoScalingGroups": [
      ]
    }
    mock_asg_resource.describe_tags.return_value = \
    {
      "Tags": [
        {
          "ResourceType": "auto-scaling-group",
          "ResourceId": "alpha0-test-instance-ServerGroup",
          "PropagateAtLaunch": "true",
          "Value": "alpha0-test-instance",
          "Key": "Name"
        }
      ]
    }
    result = ef_utils.get_autoscaling_group_properties(mock_asg_resource, "alpha0", "test-instance")
    mock_asg_resource.describe_tags.assert_called_once_with(
      Filters=[{ "Name": "Key", "Values": ["Name"] }, { "Name": "Value", "Values": ["alpha0-test-instance"]}])
    mock_asg_resource.describe_auto_scaling_groups.assert_called_with(
      AutoScalingGroupNames=["alpha0-test-instance-ServerGroup"])

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
    self.key_id = "AWS_key_id"
    self.mock_kms.encrypt.return_value = {"CiphertextBlob": self.bytes_return}
    self.mock_kms.decrypt.return_value = {"Plaintext": self.bytes_return, "KeyId": self.key_id}
    self.mock_kms.re_encrypt.return_value = self.mock_kms.encrypt.return_value

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

  def test_kms_re_encrypt_call(self):
    """Validates basic kms call parameters"""
    b64_secret = base64.b64encode(self.secret)
    ef_utils.kms_re_encrypt(self.mock_kms, self.service, self.env, b64_secret)
    self.mock_kms.re_encrypt_called_once_with(CiphertextBlob=b64_secret)

  def test_kms_re_encrypt_fails_without_b64_secret(self):
    """Ensures that function fails when passed a non-base64 encoded secret"""
    with self.assertRaises(SystemExit):
      ef_utils.kms_re_encrypt(self.mock_kms, self.service, self.env, self.secret)

  def test_kms_re_encrypt_fails_client_error(self):
    """Ensures that function fails a generic ClientError despite any special handling for specific error codes"""
    self.mock_kms.re_encrypt.side_effect = self.client_error
    b64_secret = base64.b64encode(self.secret)
    with self.assertRaises(SystemExit):
      ef_utils.kms_re_encrypt(self.mock_kms, self.service, self.env, b64_secret)


  def test_get_kms_key_alias(self):
    """Test that kms_key_alias can get a key_alias by arn"""
    service_key_alias = 'service-name'
    key_arn = 'random-ARN'
    self.mock_kms.list_aliases.return_value = {
      "Aliases": [ {"AliasName": "alias/{}".format(service_key_alias)} ]
    }
    aliases = ef_utils.kms_key_alias(self.mock_kms, key_arn)
    self.assertIn(service_key_alias, aliases)
    self.mock_kms.list_aliases.assert_called_once_with(KeyId=key_arn)

  def test_get_kms_key_alias_client_error(self):
    """Test that kms_key_alias can get a key_alias by arn"""
    service_key_alias = 'service-name'
    key_arn = 'random-ARN'
    self.mock_kms.list_aliases.side_effect = self.client_error
    with self.assertRaises(RuntimeError):
      aliases = ef_utils.kms_key_alias(self.mock_kms, key_arn)
