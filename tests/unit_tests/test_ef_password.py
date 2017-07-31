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
import unittest

from botocore.exceptions import ClientError
from mock import Mock, patch

import context_paths
ef_password = __import__("ef-password")


class TestEFPassword(unittest.TestCase):

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

    def test_generate_secret(self):
        """Check that generated secret matches the length specified and doesn't contain any special characters"""
        random_secret = ef_password.generate_secret(24)
        self.assertEqual(len(random_secret), 24)
        assert not set('[~!@#$%^&*()_+{}":;\']+$').intersection(random_secret)

    def test_kms_encrypt_call(self):
        """Validates basic kms call parameters"""
        ef_password.kms_encrypt(self.mock_kms, self.service, self.env, self.secret)
        self.mock_kms.encrypt.assert_called_once_with(
            KeyId='alias/{}-{}'.format(self.env, self.service),
            Plaintext=self.secret.encode()
        )

    def test_kms_encrypt_returns_b64(self):
        """Validate that function returns a base64 encoded value"""
        encrypted_secret = ef_password.kms_encrypt(self.mock_kms, self.service, self.env, self.secret)
        b64_return = base64.b64encode(self.bytes_return)
        self.assertEqual(b64_return, encrypted_secret)

    def test_kms_encrypt_fails_client_error(self):
        """Ensures that function fails a generic ClientError despite any special handling for specific error codes"""
        self.mock_kms.encrypt.side_effect = self.client_error
        with self.assertRaises((SystemExit, ClientError)):
            ef_password.kms_encrypt(self.mock_kms, self.service, self.env, self.secret)

    def test_kms_decrypt_call(self):
        """Validates basic kms call parameters"""
        b64_secret = base64.b64encode(self.secret)
        ef_password.kms_decrypt(self.mock_kms, b64_secret)
        self.mock_kms.decrypt.assert_called_once_with(CiphertextBlob=self.secret)

    def test_kms_decrypt_fails_without_b64_secret(self):
        """Ensures that function fails when passed a non-base64 encoded secret"""
        with self.assertRaises((SystemExit, TypeError)):
            ef_password.kms_decrypt(self.mock_kms, self.secret)

    def test_kms_decrypt_fails_client_error(self):
        """Ensures that function fails a generic ClientError despite any special handling for specific error codes"""
        self.mock_kms.decrypt.side_effect = self.client_error
        with self.assertRaises((SystemExit, ClientError)):
            ef_password.kms_decrypt(self.mock_kms, self.secret)

    def test_args(self):
        """Test parsing args with all valid values"""
        args = [self.service, self.env, "--length", "8", "--plaintext", "test", "--decrypt", "test"]
        context = ef_password.handle_args_and_set_context(args)
        self.assertEqual(context.env, self.env)
        self.assertEqual(context.service, self.service)
        self.assertEqual(context.plaintext, "test")
        self.assertEqual(context.decrypt, "test")

    def test_args_invalid_env(self):
        """Verify that an invalid environment arg raises an exception"""
        args = [self.service, "invalid_env"]
        with self.assertRaises((SystemExit, ValueError)):
            ef_password.handle_args_and_set_context(args)

    def test_args_nonint_length(self):
        """A non-integer value for the length param should raise an exception"""
        args = [self.service, self.env, "--length", "8a"]
        with self.assertRaises((SystemExit, ValueError)):
            ef_password.handle_args_and_set_context(args)

    @patch('ef-password.generate_secret', return_value="mock_secret")
    @patch('ef-password.create_aws_clients')
    @patch('ef-password.handle_args_and_set_context')
    def test_main(self, mock_context, mock_create_aws, mock_gen):
        """Test valid main() call with just service and env.
        Ensure generate_password and encrypt are called with the correct parameters"""
        context = ef_password.EFPWContext()
        context.env, context.service = self.env, self.service
        mock_context.return_value = context
        mock_create_aws.return_value = {"kms": self.mock_kms}
        ef_password.main()
        mock_gen.assert_called()
        self.mock_kms.decrypt.assert_not_called()
        self.mock_kms.encrypt.assert_called_once_with(
            KeyId='alias/{}-{}'.format(self.env, self.service),
            Plaintext="mock_secret".encode()
        )

    @patch('ef-password.generate_secret', return_value="mock_secret")
    @patch('ef-password.create_aws_clients')
    @patch('ef-password.handle_args_and_set_context')
    def test_main_plaintext(self, mock_context, mock_create_aws, mock_gen):
        """Test valid main() call with service, env, and --plaintext.
        Ensure generate_password and encrypt are called with the correct parameters"""
        context = ef_password.EFPWContext()
        context.env, context.service, context.plaintext = self.env, self.service, self.secret
        mock_context.return_value = context
        mock_create_aws.return_value = {"kms": self.mock_kms}
        ef_password.main()
        mock_gen.assert_not_called()
        self.mock_kms.decrypt.assert_not_called()
        self.mock_kms.encrypt.assert_called_once_with(
            KeyId='alias/{}-{}'.format(self.env, self.service),
            Plaintext=self.secret.encode()
        )

    @patch('ef-password.generate_secret')
    @patch('ef-password.create_aws_clients')
    @patch('ef-password.handle_args_and_set_context')
    def test_main_decrypt(self, mock_context, mock_create_aws, mock_gen):
        """Test valid main() call with service, env, and --decrypt.
        Ensure decrypt is called with the correct parameters"""
        context = ef_password.EFPWContext()
        context.env, context.service, context.decrypt = self.env, self.service, base64.b64encode(self.secret)
        mock_context.return_value = context
        mock_create_aws.return_value = {"kms": self.mock_kms}
        ef_password.main()
        mock_gen.assert_not_called()
        self.mock_kms.encrypt.assert_not_called()
        self.mock_kms.decrypt.assert_called_once_with(CiphertextBlob=self.secret)
