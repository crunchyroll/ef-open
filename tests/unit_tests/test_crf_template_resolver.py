"""
Copyright 2016-2021 Ellation, Inc.
Copyright 2021-2022 Crunchyroll, Inc.

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

from mock import call, Mock, patch

# For local application imports, context_paths must be first despite lexicon ordering
import context_paths

from crf_config import CRFConfig
from crf_template_resolver import CRFTemplateResolver
from crf_conf_utils import get_account_alias

TEST_PROFILE = get_account_alias("test")
TEST_REGION = CRFConfig.DEFAULT_REGION
TEST_ENV = "test"
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
    "alpha":{
      "blah": "unused",
      "two": "alpha two",
      "one": "alpha one"
    },
    """ +\
    "\"" + TEST_ENV + "\"" + """:{
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


class TestCRFTemplateResolver(unittest.TestCase):
  """Tests for `crf_template_resolver.py`."""

  def setUp(self):
    """
    Setup function that is run before every test

    Returns:
      None
    """
    mock_cloud_formation_client = Mock(name="Mock CloudFormation Client")
    mock_cloud_front_client = Mock(name="Mock CloudFront Client")
    mock_ec2_client = Mock(name="Mock EC2 Client")
    mock_iam_client = Mock(name="Mock IAM Client")
    mock_iam_client.get_user.return_value = {"User": {"Arn": "::::111111111:"}}
    mock_iam_client.list_account_aliases.return_value = {"AccountAliases": ["alphaaccount"]}
    mock_kms_client = Mock(name="Mock KMS Client")
    mock_lambda_client = Mock(name="Mock Lambda Client")
    mock_route_53_client = Mock(name="Mock Route 53 Client")
    mock_s3_client = Mock(name="Mock S3 Client")
    mock_sts_client = Mock(name="Mock STS Client")
    mock_waf_client = Mock(name="Mock WAF Client")
    mock_session = Mock(name="Mock Client")

    self.test_params_json = os.path.join(os.path.dirname(__file__), '../test_data/parameters/test.cnf.parameters.json')
    self.test_params_yaml = os.path.join(os.path.dirname(__file__), '../test_data/parameters/test.cnf.parameters.yml')
    self._clients = {
        "cloudformation": mock_cloud_formation_client,
        "cloudfront": mock_cloud_front_client,
        "ec2": mock_ec2_client,
        "iam": mock_iam_client,
        "kms": mock_kms_client,
        "lambda": mock_lambda_client,
        "route53": mock_route_53_client,
        "s3": mock_s3_client,
        "sts": mock_sts_client,
        "waf": mock_waf_client,
        "SESSION": mock_session
    }

  def tearDown(self):
    """
    Teardown function that is run after every test.

    Returns:
      None
    """
    pass

  @patch('crf_template_resolver.create_aws_clients')
  def test_resolution(self, mock_create_aws):
    """Do context symbols resolve correctly"""
    mock_create_aws.return_value = self._clients
    test_string = "{{one}}|{{two}}|{{/_-.}}|{{ENV}}"
    resolver = CRFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "testenv one|testenv two|slashunderscoredashdot|test")

  @patch('crf_template_resolver.create_aws_clients')
  def test_leading_dot(self, mock_create_aws):
    """Do symbols with a leading dot render correctly"""
    mock_create_aws.return_value = self._clients
    test_string = "{{.one}}"
    resolver = CRFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "testenv one")

  @patch('crf_template_resolver.create_aws_clients')
  def test_leading_dot_context(self, mock_create_aws):
    """Do context symbols with a leading dot render correctly"""
    mock_create_aws.return_value = self._clients
    test_string = "{{.ENV}}"
    resolver = CRFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), TEST_ENV)

  @patch('crf_template_resolver.create_aws_clients')
  def test_newline_literal(self, mock_create_aws):
    """Do newline literals get converted to newlines"""
    mock_create_aws.return_value = self._clients
    test_string = "foo\nbar"
    resolver = CRFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "foo\nbar")

  @patch('crf_template_resolver.create_aws_clients')
  def test_newline_literal_against_raw(self, mock_create_aws):
    """Another check to make sure newline literals are not mistakenly written as r'\n'"""
    mock_create_aws.return_value = self._clients
    test_string = "foo\nbar"
    resolver = CRFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertNotEqual(resolver.render(), r'foo\nbar')

  @patch('crf_template_resolver.create_aws_clients')
  def test_embedded_symbols(self, mock_create_aws):
    """Does a symbol built from other symbols resolve correctly"""
    mock_create_aws.return_value = self._clients
    test_string = "{{{{o}}{{ne}}}}"
    resolver = CRFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "testenv one")

  @patch('crf_template_resolver.create_aws_clients')
  def test_unresolved_symbols(self, mock_create_aws):
    """Are unresolved symbols stored and reported, and non-symbols ignored"""
    mock_create_aws.return_value = self._clients
    test_string = "{{cannot_resolve}}{{not a symbo}}{{notasymbol?}}{{cannot_resolve}}"
    resolver = CRFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.unresolved_symbols(), set(["cannot_resolve"]))

  @patch('crf_template_resolver.create_aws_clients')
  def test_hierarchical_overlays(self, mock_create_aws):
    """Is the hierarchy of default..env applied correctly"""
    mock_create_aws.return_value = self._clients
    test_string = "{{one}}|{{two}}|{{my-thing}}"
    resolver = CRFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "testenv one|testenv two|my-hyphen-thing")

  @patch('crf_template_resolver.create_aws_clients')
  def test_context_vars_protected(self, mock_create_aws):
    """Context vars like {{ENV}} are not overridden even if present in template"""
    mock_create_aws.return_value = self._clients
    test_string = "{{ENV}}"
    resolver = CRFTemplateResolver(profile=TEST_PROFILE, env=TEST_ENV, region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), TEST_ENV)

  @patch('crf_template_resolver.create_aws_clients')
  def test_fully_qualified_env(self, mock_create_aws):
    """Does {{ENV_FULL}} resolve correctly"""
    mock_create_aws.return_value = self._clients
    # alpha0
    test_string = "{{ENV_FULL}}"
    resolver = CRFTemplateResolver(profile=get_account_alias("alpha0"),
                                  env="alpha0", region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "alpha0")
    # prod
    resolver = CRFTemplateResolver(profile=get_account_alias("test"),
                                  env="test", region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "test")
    # mgmt.testaccount
    resolver = CRFTemplateResolver(profile=get_account_alias("mgmt.testaccount"),
                                  env="mgmt.testaccount", region=TEST_REGION, service=TEST_SERVICE)
    resolver.load(test_string, PARAMS)
    self.assertEqual(resolver.render(), "mgmt.testaccount")

  @patch('crf_template_resolver.create_aws_clients')
  def test_load_json_file(self, mock_create_aws):
    """Does {{one}} resolve correctly from json parameters file"""
    mock_create_aws.return_value = self._clients
    test_string = "{{one}}"
    resolver = CRFTemplateResolver(profile=get_account_alias("alpha0"),
                                  env="alpha0", region=TEST_REGION, service=TEST_SERVICE)
    with open(self.test_params_json) as json_file:
      resolver.load(test_string, json_file)
    self.assertEqual(resolver.render(), "alpha one")

  @patch('crf_template_resolver.create_aws_clients')
  def test_load_yaml_file(self, mock_create_aws):
    """Does {{one}} resolve correctly from yaml parameters file"""
    mock_create_aws.return_value = self._clients
    test_string = "{{one}}"
    resolver = CRFTemplateResolver(profile=get_account_alias("alpha0"),
                                  env="alpha0", region=TEST_REGION, service=TEST_SERVICE)
    with open(self.test_params_yaml) as yaml_file:
      resolver.load(test_string, yaml_file)
    self.assertEqual(resolver.render(), "alpha one")

  @patch('crf_template_resolver.create_aws_clients')
  def test_render_multiline_string_from_string(self, mock_create_aws):
    """Does {{multi}} resolve correctly as a multiline string from yaml parameters file"""
    mock_create_aws.return_value = self._clients
    test_string = "{{multi}}"
    resolver = CRFTemplateResolver(profile=get_account_alias("test"),
                                  env="test", region=TEST_REGION, service=TEST_SERVICE)
    with open(self.test_params_json) as json_file:
      resolver.load(test_string, json_file)
    self.assertEqual(resolver.render(), "thisisareallylongstringthatcoversmultiple\nlinesfortestingmultilinestrings")

  @patch('crf_template_resolver.create_aws_clients')
  def test_render_multiline_string_from_list(self, mock_create_aws):
    """Does {{multi}} resolve correctly as a multiline string from yaml parameters file"""
    mock_create_aws.return_value = self._clients
    test_string = "{{multi2}}"
    resolver = CRFTemplateResolver(profile=get_account_alias("test"),
                                  env="test", region=TEST_REGION, service=TEST_SERVICE)
    with open(self.test_params_json) as json_file:
      resolver.load(test_string, json_file)
    self.assertEqual(resolver.render(), "one\ntwo\nthree")

  @patch('crf_template_resolver.create_aws_clients')
  def test_render_multiline_string(self, mock_create_aws):
    """Does {{multi}} resolve correctly as a multiline string from yaml parameters file"""
    mock_create_aws.return_value = self._clients
    test_string = "{{multi}}"
    resolver = CRFTemplateResolver(profile=get_account_alias("test"),
                                  env="test", region=TEST_REGION, service=TEST_SERVICE)
    with open(self.test_params_yaml) as yaml_file:
      resolver.load(test_string, yaml_file)
    self.assertEqual(resolver.render(), "thisisareallylongstringthatcoversmultiple\nlinesfortestingmultilinestrings")
