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

from mock import Mock, patch, mock_open

from efopen import ef_site_config


class TestEFSiteConfig(unittest.TestCase):
  """
  TestEFSiteConfig class for ef_site_config testing.
  """

  def test_site_config_parse(self):
    """Test parsing a site config"""
    mock_ef_site_config_file = os.path.join(os.path.dirname(__file__), '../test_data/ef_site_config.yml')
    mock_data = open(mock_ef_site_config_file).read()
    with patch('__builtin__.open', mock_open(read_data=mock_data)) as mock_file:
      test_config = ef_site_config.EFSiteConfig().load()
      self.assertEqual(test_config["ENV_ACCOUNT_MAP"]["test"], "testaccount")
