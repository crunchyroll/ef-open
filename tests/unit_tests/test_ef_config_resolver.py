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

# For local application imports, context_paths must be first despite lexicon ordering
from . import context_paths

from efopen.ef_config import EFConfig
from efopen.ef_config_resolver import EFConfigResolver


class TestEFConfigResolver(unittest.TestCase):
  """Tests for 'ef_config_resolver.py'"""

  def test_account_alias_of_env(self):
    """Does accountaliasofenv,prod resolve to the prod account alias"""
    ef_config_resolver = EFConfigResolver()
    result_config_data = ef_config_resolver.lookup("accountaliasofenv,test")
    if result_config_data is None:
      result_config_data = ''
    self.assertRegexpMatches(result_config_data, "^testaccount$")

  def test_config_custom_data(self):
    target_custom_data = "custom_data"
    EFConfig.CUSTOM_DATA = {"mock_data": "custom_data"}

    ef_config_resolver = EFConfigResolver()
    result_custom_data = ef_config_resolver.lookup("customdata,mock_data")
    self.assertEquals(result_custom_data, target_custom_data)

  def test_config_custom_data_no_data(self):
    ef_config_resolver = EFConfigResolver()
    result_custom_data = ef_config_resolver.lookup("customdata,mock_data")
    self.assertEquals(result_custom_data, None)

  def test_config_custom_data_missing_lookup(self):
    EFConfig.CUSTOM_DATA = {}

    ef_config_resolver = EFConfigResolver()
    result_custom_data = ef_config_resolver.lookup("customdata,mock_data")
    self.assertEquals(result_custom_data, None)
