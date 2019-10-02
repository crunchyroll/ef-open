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
import unittest

from mock import MagicMock, Mock, patch, mock_open

from efopen.ef_site_config import EFSiteConfig


class TestEFSiteConfig(unittest.TestCase):
  """
  TestEFSiteConfig class for ef_site_config testing.
  """

  def setUp(self):
    test_ef_site_config_file = os.path.join(os.path.dirname(__file__), '../test_data/ef_site_config.yml')
    self.test_config = open(test_ef_site_config_file).read()

  def test_site_load_local_file(self):
    """Test parsing a site config"""
    with patch('__builtin__.open', mock_open(read_data=self.test_config)) as mock_file:
      test_config = EFSiteConfig().load_from_local_file()
      self.assertEqual(test_config["ENV_ACCOUNT_MAP"]["test"], "testaccount")

  def test_site_config_load_local_on_non_ec2(self):
    with patch('efopen.ef_utils.whereami') as whereami,\
         patch.object(EFSiteConfig,
                      'load_from_local_file') as mock_file_load:

        mock_file_load.return_value = {"Configuration": "file"}
        test_config = EFSiteConfig().load()
        # whereami return value doesn't matter
        whereami.assert_called_once()
        mock_file_load.assert_called_once()
        self.assertDictEqual(test_config, mock_file_load.return_value)

  def test_site_config_load_from_ssm_on_ec2(self):
    with patch('efopen.ef_utils.whereami') as whereami,\
         patch.object(EFSiteConfig,
                      'load_from_ssm') as mock_ssm_load:

      mock_ssm_load.return_value = {"Configuration": "file"}
      whereami.return_value = 'ec2'
      test_config = EFSiteConfig().load()
      whereami.assert_called_once()
      mock_ssm_load.assert_called_once()
      self.assertDictEqual(test_config, mock_ssm_load.return_value)

  def test_load_from_ssm(self):
    with patch('boto3.client') as boto3_client_func:
      config_value = 'Hello world'
      ssm_client_mock = Mock(name='ssm_client_mock')
      boto3_client_func.return_value = ssm_client_mock
      ssm_parameter =  {'Parameter': {'Value': config_value}}
      get_parameter_mock = ssm_client_mock.get_parameter
      get_parameter_mock.return_value = ssm_parameter

      test_config = EFSiteConfig().load_from_ssm()

      self.assertEqual(test_config, config_value)
      boto3_client_func.assert_called_once_with('ssm', region_name='us-west-2')
      get_parameter_mock.assert_called_once_with(Name='/efopen/ef_site_config')
