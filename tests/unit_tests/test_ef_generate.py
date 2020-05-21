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

import os
import json
import unittest

from botocore.exceptions import ClientError
from mock import Mock, patch

import context_paths
from ef_context import EFContext

import ef_generate


class TestEFGenerate(unittest.TestCase):
  def setUp(self):
    self.role_name = "global-test-role"
    self.service_name = "proto0-test-service"
    self.service_type = "http_service"
    self.service_registry_file = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                              '../test_data/test_service_registry_1.json'))
    with open(self.service_registry_file, "r") as sr:
      self.service_registry = json.load(sr)
    self.malformed_policy_response = {'Error': {'Code': 'MalformedPolicyDocumentException',
                                                'Message': 'Error creating key'}}
    self.malformed_policy_client_error = ClientError(self.malformed_policy_response, "create_key")
    self.not_found_response = {'Error': {'Code': 'NotFoundException', 'Message': 'Error describing key'}}
    self.not_found_client_error = ClientError(self.not_found_response, "describe_key")
    self.mock_iam = Mock(name="mocked iam client")
    self.mock_iam.attach_role_policy.return_value = {}
    self.mock_kms = Mock(name="mocked kms client")
    self.mock_kms.create_key.return_value = {"KeyMetadata": {"KeyId": "1234"}}
    self.mock_kms.describe_key.side_effect = self.not_found_client_error
    # This is literally what the official documentation states is the response, a bunch of ... as a placeholder
    self.mock_kms.enable_key_rotation.return_value = {'ResponseMetadata': {'...': '...'}
}
    ef_generate.CONTEXT = EFContext()
    ef_generate.CONTEXT.commit = True
    ef_generate.CONTEXT.account_id = "1234"
    ef_generate.CLIENTS = {"kms": self.mock_kms, "iam": self.mock_iam}

  def test_attach_managed_policies(self):
    """
    Check that when an existing key is not found that the create key/alias methods are called with the correct
    parameters.
    """
    ef_generate.conditionally_attach_aws_managed_policies(self.role_name,
                                                      self.service_registry['fixtures']['test-role'])

    self.mock_iam.attach_role_policy.assert_called_with(
      RoleName=self.role_name,
      PolicyArn='arn:aws:iam::aws:policy/{}'.format(self.service_registry['fixtures']['test-role']['aws_managed_policies'][0])
    )

  def test_attach_customer_managed_policies(self):
    """
    Check that when an existing key is not found that the create key/alias methods are called with the correct
    parameters.
    """
    ef_generate.conditionally_attach_customer_managed_policies(self.role_name,
                                                      self.service_registry['fixtures']['test-role'])

    self.mock_iam.attach_role_policy.assert_called_with(
      RoleName=self.role_name,
      PolicyArn='arn:aws:iam::{}:policy/{}'.format(
        ef_generate.CONTEXT.account_id,
        self.service_registry['fixtures']['test-role']['customer_managed_policies'][0])
    )

  def test_not_service_type_for_managed_policy(self):
    """
    Validates that a managed policy is not attached for unsupported service types
    """
    self.service_type = {"type": "invalid_service"}
    ef_generate.conditionally_attach_aws_managed_policies(self.role_name, self.service_type)

    self.mock_iam.attach_role_policy.assert_not_called()

  def test_no_aws_managed_policies_key_in_service(self):
    """
    Validates that a managed policy is not attached services without the 'aws_managed_policies' key
    """
    ef_generate.conditionally_attach_aws_managed_policies(self.role_name,
                                                      self.service_registry['fixtures']['test-role-2'])

    self.mock_iam.attach_role_policy.assert_not_called()

  def test_create_kms_key(self):
    """
    Check that when an existing key is not found that the create key/alias methods are called with the correct
    parameters.
    """
    ef_generate.conditionally_create_kms_key(self.service_name, self.service_type)

    self.mock_kms.create_key.assert_called()
    self.mock_kms.create_alias.assert_called_with(
      AliasName='alias/{}'.format(self.service_name),
      TargetKeyId='1234'
    )
    self.mock_kms.enable_key_rotation.assert_called()

  def test_create_kms_key_subservice(self):
    """
    Verify that subservices (formatted as service-name.subservice in the service registry) are created using an
    underscore in place of a period for the key alias.
    """
    subservice = self.service_name + ".subservice"
    ef_generate.conditionally_create_kms_key(subservice, self.service_type)

    self.mock_kms.create_key.assert_called()
    self.mock_kms.create_alias.assert_called_with(
      AliasName='alias/{}'.format(self.service_name + "_subservice"),
      TargetKeyId='1234'
    )
    self.mock_kms.enable_key_rotation.assert_called()

  def test_kms_key_already_exists(self):
    """
    Check that when an existing key is found the create key/alias methods are not called.
    """
    self.mock_kms.describe_key.side_effect = None
    self.mock_kms.describe_key.return_value = {"KeyMetadata": {"KeyId": "1234"}}
    ef_generate.conditionally_create_kms_key(self.service_name, self.service_type)

    self.mock_kms.create_key.assert_not_called()
    self.mock_kms.create_alias.assert_not_called()
    self.mock_kms.enable_key_rotation.assert_called()

  def test_kms_service_type_fixture(self):
    """
    Verify that a KMS key is created when of service_type "aws_fixture"
    """
    self.service_type = "aws_fixture"
    ef_generate.conditionally_create_kms_key(self.service_name, self.service_type)

    self.mock_kms.create_key.assert_called()
    self.mock_kms.create_alias.assert_called_with(
      AliasName='alias/{}'.format(self.service_name),
      TargetKeyId='1234'
    )
    self.mock_kms.enable_key_rotation.assert_called()

  def test_not_kms_service_type(self):
    """
    Validates that a key/alias is not created for unsupported service types
    """
    self.service_type = "invalid_service"
    ef_generate.conditionally_create_kms_key(self.service_name, self.service_type)

    self.mock_kms.describe_key.assert_not_called()
    self.mock_kms.create_key.assert_not_called()
    self.mock_kms.create_alias.assert_not_called()

  @patch('time.sleep', return_value=None)
  def test_kms_eventual_consistency_resilience(self, patched_time_sleep):
    """
    Validate that conditionally_create_kms_key will account for aws eventual consistency when attempting to
    reference a newly created ec2 role. Providing three exceptions and then success.
    """
    self.mock_kms.create_key.side_effect = [
      self.malformed_policy_client_error,
      self.malformed_policy_client_error,
      self.malformed_policy_client_error,
      {"KeyMetadata": {"KeyId": "1234"}}
    ]
    ef_generate.conditionally_create_kms_key(self.service_name, self.service_type)

    self.mock_kms.create_alias.assert_called_with(
      AliasName='alias/{}'.format(self.service_name),
      TargetKeyId='1234'
    )

  @patch('time.sleep', return_value=None)
  def test_kms_create_key_eventual_consistency_failure(self, patched_time_sleep):
    """
    Validate that create_key call fails after 5 MalformedPolicyDocumentException's.
    """
    self.mock_kms.create_key.side_effect = self.malformed_policy_client_error
    with self.assertRaises(SystemExit) as error:
      ef_generate.conditionally_create_kms_key(self.service_name, self.service_type)
    self.assertEquals(error.exception.code, 1)
