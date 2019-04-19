"""
Copyright 2016-2018 Ellation, Inc.

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

from __future__ import print_function
import os
from StringIO import StringIO
import unittest

from mock import Mock, patch

# For local application imports, context_paths must be first despite lexicon ordering
import context_paths

from ef_instanceinit_config_reader import EFInstanceinitConfigReader


class TestEFInstanceInitConfigReader(unittest.TestCase):
  """Tests for 'ef_instanceinit_config_reader.py'"""

  def setUp(self):
    self.mock_s3_resource = Mock(name="mocked S3 resource")
    self.mock_logger = Mock(name="mocked logger object")

  @patch('ef_conf_utils.get_template_parameters_file')
  def test_config_parameters_from_file(self, mock_params_file):
    """Test basic function"""
    base_path = os.path.join(os.path.dirname(__file__), "../test_data")
    parameters_file_path = os.path.join(os.path.dirname(__file__), "../test_data/parameters/test.cnf.parameters.yml")
    mock_params_file.return_value = parameters_file_path
    config_reader = EFInstanceinitConfigReader("file", base_path, self.mock_logger)
    config_reader.next()
    self.assertEquals(config_reader.parameters["dest"]["path"], "/srv/test-instance/test.cnf")

  @patch('ef_utils.get_template_parameters_s3')
  def test_config_parameters_from_s3(self, mock_params_key):
    """Test basic function"""
    mock_params_key.return_value = 'test-instance/parameters/test.cnf.parameters.json'
    mock_bucket_object = Mock(name="mocked bucket object")
    mock_bucket_object.size = 1
    self.mock_s3_resource.Bucket.return_value.objects.filter.return_value = [mock_bucket_object]
    mock_object_return = {"Body": StringIO("{'dest': {'path': '/srv/test-instance/test.cnf'}}")}
    self.mock_s3_resource.Object.return_value.get.return_value = mock_object_return
    config_reader = EFInstanceinitConfigReader("s3", "test-instance", self.mock_logger, self.mock_s3_resource)
    config_reader.next()
    self.assertEquals(config_reader.parameters["dest"]["path"], "/srv/test-instance/test.cnf")
