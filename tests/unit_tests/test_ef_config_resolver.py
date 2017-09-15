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
import context_paths
from ef_config_resolver import EFConfigResolver

class TestEFConfigResolver(unittest.TestCase):
  """Tests for 'ef_config_resolver.py'"""

  def test_account_alias_of_env(self):
    """Does accountaliasofenv,prod resolve to the prod account alias"""
    test_string = "accountaliasofenv,prod"
    resolver = EFConfigResolver()
    self.assertRegexpMatches(resolver.lookup(test_string), "^ellation$")


if __name__ == '__main__':
  unittest.main()
