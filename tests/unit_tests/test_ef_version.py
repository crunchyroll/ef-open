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

import base64
import os
import sys
import unittest
from datetime import datetime

from botocore.exceptions import ClientError
from mock import Mock, patch

import context_paths
from ef_version_resolver import EFVersionResolver

ef_version = __import__("ef-version")


class TestEFVersion(unittest.TestCase):
  def setUp(self):
    self.build_number = "000001"
    self.commit_hash = "sfasdf10984jhoksfgls89734hd8i4w98sf"
    self.env = "internal"
    self.history = "text"
    self.key = "ami-id"
    self.location = "https://s3-us-west-2.amazonaws.com/ellation-cx-proto3-static/foo/dist-hash"
    self.noprecheck = None
    self.service = "test-instance"
    self.service_name = "test-instance"
    self.value = "11111111"
    self.mock_version = Mock(name="mocked Version object")
    self.service_registry_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '../test_data/test_service_registry_1.json'))

    # Shared or context derived mocks
    self.aws_client = Mock(name="mocked aws client")
    self.mock_version.value = self.value
    self.mock_version.location = self.location
    self.service_registry = Mock(name="mocked service registry")
    self.service_registry.filespec = self.service_registry_file
    self.service_registry.service_record.return_value = {"type": "aws_ec2"}
    self.version = Mock(name="mocked version object")


  def test_lookup_key(self):
    """Verify that a valid instance type returns """
    key = ef_version.lookup_key(self)
    self.assertEqual(key, self.key)

  def test_lookup_key_invalid_type(self):
    """Verify that an invalid instance type raises an exception"""
    self.service_registry.service_record.return_value = None
    with self.assertRaises(SystemExit):
      ef_version.lookup_key(self)

  def test_lookup_key_invalid_service(self):
    """Verify that an invalid service raises an exception"""
    self.service_registry.service_record.return_value = None
    with self.assertRaises(SystemExit):
      ef_version.lookup_key(self)

  def test_args_get(self):
    """Test parsing args with all valid values for get"""
    args = [self.service, self.env, "--get", "--sr", "{}".format(self.service_registry_file)]
    context = ef_version.handle_args_and_set_context(args)
    self.assertEqual(context.env, self.env)
    self.assertEqual(context.service_name, self.service_name)
    self.assertEqual(context.service_registry.filespec, self.service_registry_file)

  def test_args_set(self):
    """Test parsing args with all valid values for set"""
    args = [self.service, self.env, "--set", self.value, "--location", self.location, "--build", self.build_number, "--commit_hash", self.commit_hash, "--sr", "{}".format(self.service_registry_file)]
    context = ef_version.handle_args_and_set_context(args)
    self.assertEqual(context.build_number, self.build_number)
    self.assertEqual(context.commit_hash, self.commit_hash)
    self.assertEqual(context.env, self.env)
    self.assertEqual(context.location, self.location)
    self.assertEqual(context.service_name, self.service_name)
    self.assertEqual(context.service_registry.filespec, self.service_registry_file)
    self.assertEqual(context.value, self.value)

  def test_args_history(self):
    """Test parsing args with all valid values for history"""
    args = [self.service, self.env, "--history", self.history, "--sr", "{}".format(self.service_registry_file)]
    context = ef_version.handle_args_and_set_context(args)
    self.assertEqual(context.env, self.env)
    self.assertEqual(context.history, self.history)
    self.assertEqual(context.service_name, self.service_name)
    self.assertEqual(context.service_registry.filespec, self.service_registry_file)

  def test_args_invalid_env(self):
    """Verify that an invalid environment arg raises an exception"""
    args = [self.service, "invalid_env"]
    with self.assertRaises(SystemExit):
      ef_version.handle_args_and_set_context(args)

  @patch('ef-version.isfunction')
  def test_noprecheck(self, mock_isfunction):
    """Test precheck resolves the correct precheck method"""
    mock_isfunction.return_value = True
    self.noprecheck = True
    self.assertTrue(ef_version.precheck(self))
    mock_isfunction.assert_not_called()

  @patch('ef-version.isfunction')
  @patch('ef-version.globals')
  def test_precheck(self, mock_globals, mock_isfunction):
    mock_isfunction.return_value = True
    mock_precheck_method = Mock(name='mock precheck method')
    mock_precheck_method.return_value = True
    mock_globals.return_value = {"precheck_ami_id": mock_precheck_method}
    self.assertTrue(ef_version.precheck(self))
    mock_precheck_method.assert_called_once()

  @patch('ef-version.Version')
  @patch('urllib2.urlopen')
  def test_precheck_dist_hash(self, mock_urlopen, mock_version_object):
    """Test precheck of dist hash version"""
    mock_version_object.return_value = self.mock_version
    mock_s3_response = Mock(name='mock s3 response')
    mock_s3_response.getcode.return_value = 200
    mock_s3_response.read.return_value = self.value
    mock_urlopen.return_value = mock_s3_response
    self.assertTrue(ef_version.precheck_dist_hash(self))

  @patch('ef-version.Version')
  @patch('urllib2.urlopen')
  def test_precheck_dist_hash_s3_404(self, mock_urlopen, mock_version_object):
    """Test precheck to validate error thrown on a Non-200 response from s3"""
    mock_version_object.return_value = self.mock_version
    mock_s3_response = Mock(name='mock s3 response')
    mock_s3_response.getcode.return_value = 404
    mock_urlopen.return_value = mock_s3_response
    with self.assertRaises(IOError):
      ef_version.precheck_dist_hash(self)

  @patch('ef-version.Version')
  @patch('urllib2.urlopen')
  def test_precheck_dist_hash_urllib_error(self, mock_urlopen, mock_version_object):
    """Test preckek to validate error thrown on url error"""
    mock_version_object.return_value = self.mock_version
    mock_s3_response = Mock(name='mock s3 response')
    mock_urlopen.return_value = mock_s3_response
    mock_urlopen.side_effect = IOError
    with self.assertRaises(IOError):
      ef_version.precheck_dist_hash(self)

  @patch('ef-version.Version')
  @patch('urllib2.urlopen')
  def test_precheck_dist_hash_version_none(self, mock_urlopen, mock_version_object):
    """Test precheck_dist_hash when current version is none"""
    self.mock_version.value = None
    mock_version_object.return_value = self.mock_version
    self.assertTrue(ef_version.precheck_dist_hash(self))
