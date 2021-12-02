"""
Copyright 2016-2017 Crunchyroll, Inc.

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
import context_paths

from crf_config import CRFConfig
from crf_config_resolver import CRFConfigResolver


class TestCRFConfigResolver(unittest.TestCase):
  """Tests for 'crf_config_resolver.py'"""

  def test_account_alias_of_env(self):
    """Does accountaliasofenv,prod resolve to the prod account alias"""
    crf_config_resolver = CRFConfigResolver()
    result_config_data = crf_config_resolver.lookup("accountaliasofenv,test")
    if result_config_data is None:
      result_config_data = ''
    self.assertRegexpMatches(result_config_data, "^testaccount$")

  def test_config_custom_data(self):
    target_custom_data = "custom_data"
    CRFConfig.CUSTOM_DATA = {"mock_data": "custom_data"}

    crf_config_resolver = CRFConfigResolver()
    result_custom_data = crf_config_resolver.lookup("customdata,mock_data")
    self.assertEquals(result_custom_data, target_custom_data)

  def test_config_custom_data_no_data(self):
    crf_config_resolver = CRFConfigResolver()
    result_custom_data = crf_config_resolver.lookup("customdata,mock_data")
    self.assertEquals(result_custom_data, None)

  def test_config_custom_data_missing_lookup(self):
    CRFConfig.CUSTOM_DATA = {}

    crf_config_resolver = CRFConfigResolver()
    result_custom_data = crf_config_resolver.lookup("customdata,mock_data")
    self.assertEquals(result_custom_data, None)
