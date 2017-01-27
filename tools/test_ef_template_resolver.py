"""
Copyright 2016 Ellation, Inc.

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

from ef_config import EFConfig
from ef_template_resolver import EFTemplateResolver
from ef_utils import get_account_alias

TEST_PROFILE = get_account_alias("proto0")
TEST_REGION = EFConfig.DEFAULT_REGION
TEST_ENV = "proto0"
TEST_SERVICE = "none"

PARAMS = """{
  "params":{
    "default":{
      "one": "default one",
      "two": "default two",
      "o": "o",
      "ne": "ne",
      "/_-.": "slashunderscoredashdot",
      ".": "dot",
      "my-thing": "my-hyphen-thing"
    },
    "proto":{
      "blah": "unused",
      "two": "proto two",
      "one": "proto one"
    },
    """ +\
    "\"" + TEST_ENV + "\"" +""":{
      "one": "testenv one",
      "two": "testenv two",
      "ENV": "myenvironmentshouldnotoverride"
    },
    "staging": {
      "one": "staging one"
    }
  }
}
"""

ILLEGAL_COMMA_PARAMS = """{
  "params":{
    "legal_key_name": "valid_value",
    "illegal,key_name": "valid value"
  }
}
"""

class TestEFTemplateResolver(unittest.TestCase):
  """Tests for `ef_template_resolver.py`."""

  def test_resolution(self):
    """Do context symbols resolve correctly"""
    test_string = "{{one}}|{{two}}|{{/_-.}}|{{ENV}}"
    resolver = EFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "testenv one|testenv two|slashunderscoredashdot|proto0")

  def test_embedded_symbols(self):
    """Does a symbol built from other symbols resolve correctly"""
    test_string = "{{{{o}}{{ne}}}}"
    resolver = EFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "testenv one")

  def test_unresolved_symbols(self):
    """Are unresolved symbols stored and reported, and non-symbols ignored"""
    test_string = "{{cannot_resolve}}{{not a symbo}}{{notasymbol?}}{{cannot_resolve}}"
    resolver = EFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.unresolved_symbols(), set(["cannot_resolve"]))

  def test_hierarchical_overlays(self):
    """Is the hierarchy of default..env applied correctly"""
    test_string = "{{one}}|{{two}}|{{my-thing}}"
    resolver = EFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "testenv one|testenv two|my-hyphen-thing")

  def test_context_vars_protected(self):
    """Context vars like {{ENV}} are not overridden even if present in template"""
    test_string = "{{ENV}}"
    resolver = EFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), TEST_ENV)

  def test_fully_qualified_env(self):
    """Does {{ENV_FULL}} resolve correctly"""
    # proto0
    test_string = "{{ENV_FULL}}"
    resolver = EFTemplateResolver(profile=get_account_alias("proto0"), env="proto0", region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "proto0")
    # prod
    resolver = EFTemplateResolver(profile=get_account_alias("prod"), env="prod", region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "prod")
    # mgmt.ellationeng
    resolver = EFTemplateResolver(profile=get_account_alias("mgmt.ellationeng"), env="mgmt.ellationeng", region=TEST_REGION,
                                  service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "mgmt.ellationeng")


if __name__ == '__main__':
  unittest.main()
