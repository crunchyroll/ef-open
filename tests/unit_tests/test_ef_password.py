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
import base64

from botocore.exceptions import ClientError
from mock import Mock, patch

import context_paths
ef_password = __import__("ef-password")


class TestEFPassword(unittest.TestCase):

    def setUp(self):
        self.service = "test-service"
        self.env = "test0"
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

    @patch('sys.argv')
    def test_ef_password_fails_non_int_length(self, patched_argv):
        patched_argv.return_value = ['test', self.service, self.env]
