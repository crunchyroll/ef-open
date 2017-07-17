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

from mock import Mock

from ef_context import EFContext
ef_generate = __import__("ef-generate")


class TestEFGenerate(unittest.TestCase):

    def setUp(self):
        self.service_name = "proto0-test-service"
        self.service_type = "http_service"
        ef_generate.CONTEXT = EFContext()
        ef_generate.CONTEXT.commit = True
        ef_generate.CONTEXT.account_id = "1234"
        self.mock_kms = Mock(name="mocked kms client")
        self.mock_kms.describe_key.return_value = None
        self.mock_kms.create_key.return_value = {"KeyMetadata": {"KeyId": "1234"}}
        ef_generate.CLIENTS = {
            "kms": self.mock_kms
        }

    def test_create_kms_key(self):
        ef_generate.conditionally_create_kms_key(self.service_name, self.service_type)

        self.mock_kms.describe_key.assert_called()
        self.mock_kms.create_key.assert_called()
        self.mock_kms.create_alias.assert_called_with(
            AliasName='alias/{}'.format(self.service_name),
            TargetKeyId='1234'
        )

    def test_kms_key_already_exists(self):
        self.mock_kms.describe_key.return_value = Mock()
        ef_generate.conditionally_create_kms_key(self.service_name, self.service_type)

        self.mock_kms.create_key.assert_not_called()
        self.mock_kms.create_alias.assert_not_called()
