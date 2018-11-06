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

import datetime
import os
import StringIO
import unittest

from dateutil.tz import tzutc

from mock import Mock, patch

import context_paths
from botocore.exceptions import ClientError

import ef_version


class TestEFVersion(unittest.TestCase):
  """
  TestEFVersion class for ef_version testing.

  Setup initializes self in the same manner we initialize ef-context to ensure the appropriate
  members are available when testing. This is necessary given the pattern of passing the context
  object as a parameter to methods.
  """

  def setUp(self):
    self.build_number = "000001"
    self.commit_hash = "sfasdf10984jhoksfgls89734hd8i4w98sf"
    self.env = "test"
    self.env_full = "global.testaccount"
    self.history = "text"
    self.key = "ami-id"
    self.location = "https://s3-us-west-2.amazonaws.com/ellation-cx-proto3-static/foo/dist-hash"
    self.noprecheck = None
    self.parsed_env_full = "global"
    self.service = "test-instance"
    self.service_name = "test-instance"
    self.value = "11111111"
    self.mock_version = Mock(name="mocked Version object")
    self.service_registry_file = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                              '../test_data/test_service_registry_1.json'))

    # Shared or context derived mocks
    self.aws_client = Mock(name="mocked aws client")
    self.mock_version.value = self.value
    self.mock_version.location = self.location
    self.service_registry = Mock(name="mocked service registry")
    self.service_registry.filespec = self.service_registry_file
    self.service_registry.service_record.return_value = {"type": "aws_ec2"}
    self.version = Mock(name="mocked version object")

  def test_validate_context(self):
    """Verify that a valid instance type returns True"""
    self.assertTrue(ef_version.validate_context(self))

  def test_validate_context_invalid_key(self):
    """Verify that a invalid key raises an exception"""
    self.key = 'ami-i'
    with self.assertRaises(SystemExit):
      ef_version.validate_context(self)

  def test_validate_context_invalid_service(self):
    """Verify that an invalid instance service raises an exception"""
    self.service_registry.service_record.return_value = None
    with self.assertRaises(SystemExit):
      ef_version.validate_context(self)

  def test_validate_context_invalid_type(self):
    """Verify that an invalid type raises an exception"""
    self.service_registry.service_record.return_value = {"type": "aws_ec"}
    with self.assertRaises(SystemExit):
      ef_version.validate_context(self)

  def test_args_get(self):
    """Test parsing args with all valid values for get"""
    args = [self.service, self.key, self.env, "--get", "--sr", "{}".format(self.service_registry_file)]
    context = ef_version.handle_args_and_set_context(args)
    self.assertEqual(context.env, self.env)
    self.assertEqual(context.service_name, self.service_name)
    self.assertEqual(context.service_registry.filespec, self.service_registry_file)

  def test_args_invalid_env(self):
    """Verify that an invalid environment arg raises an exception"""
    args = [self.service, self.key, "invalid_env"]
    with self.assertRaises(SystemExit):
      ef_version.handle_args_and_set_context(args)

  def test_args_get_parse_env_full(self):
    """Test parsing args with all valid values for get using account scoped env"""
    args = [self.service, self.key, self.env_full, "--get", "--sr", "{}".format(self.service_registry_file)]
    context = ef_version.handle_args_and_set_context(args)
    self.assertEqual(context.env, self.parsed_env_full)
    self.assertEqual(context.service_name, self.service_name)
    self.assertEqual(context.service_registry.filespec, self.service_registry_file)

  def test_args_get_force_env_full(self):
    """Test parsing args with all valid values for get and add --env_full flag"""
    args = [self.service, self.key, self.env_full, "--get", "--sr", "{}".format(self.service_registry_file),  "--force_env_full"]
    context = ef_version.handle_args_and_set_context(args)
    self.assertEqual(context.env, self.env_full)
    self.assertEqual(context.service_name, self.service_name)
    self.assertEqual(context.service_registry.filespec, self.service_registry_file)

  def test_args_get_force_env_full_env_not_account_scoped(self):
    """Test parsing args with all valid values for get and add --env_full flag"""
    args = [self.service, self.key, self.env, "--get", "--sr", "{}".format(self.service_registry_file),  "--force_env_full"]
    context = ef_version.handle_args_and_set_context(args)
    self.assertEqual(context.env, self.env)
    self.assertEqual(context.service_name, self.service_name)
    self.assertEqual(context.service_registry.filespec, self.service_registry_file)

  def test_args_set(self):
    """Test parsing args with all valid values for set"""
    args = [self.service, self.key, self.env, "--set", self.value, "--location", self.location, "--build",
            self.build_number, "--commit_hash", self.commit_hash, "--sr", "{}".format(self.service_registry_file)]
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
    args = [self.service, self.key, self.env, "--history", self.history, "--sr", "{}".format(self.service_registry_file)]
    context = ef_version.handle_args_and_set_context(args)
    self.assertEqual(context.env, self.env)
    self.assertEqual(context.history, self.history)
    self.assertEqual(context.service_name, self.service_name)
    self.assertEqual(context.service_registry.filespec, self.service_registry_file)

  @patch('ef_version.isfunction')
  def test_noprecheck(self, mock_isfunction):
    """Test precheck resolves the correct precheck method"""
    mock_isfunction.return_value = True
    self.noprecheck = True
    self.assertTrue(ef_version.precheck(self))
    mock_isfunction.assert_not_called()

  @patch('ef_version.isfunction')
  @patch('ef_version.globals')
  def test_precheck(self, mock_globals, mock_isfunction):
    """Test precheck returns correct method"""
    mock_isfunction.return_value = True
    mock_precheck_method = Mock(name='mock precheck method')
    mock_precheck_method.return_value = True
    mock_globals.return_value = {"precheck_ami_id": mock_precheck_method}
    self.assertTrue(ef_version.precheck(self))
    mock_precheck_method.assert_called_once()

  @patch('ef_version.Version')
  @patch('urllib2.urlopen')
  def test_precheck_dist_hash(self, mock_urlopen, mock_version_object):
    """Test precheck of dist hash version"""
    mock_version_object.return_value = self.mock_version
    mock_s3_response = Mock(name='mock s3 response')
    mock_s3_response.getcode.return_value = 200
    mock_s3_response.read.return_value = self.value
    mock_urlopen.return_value = mock_s3_response
    self.assertTrue(ef_version.precheck_dist_hash(self))

  @patch('ef_version.Version')
  @patch('urllib2.urlopen')
  def test_precheck_dist_hash_s3_404(self, mock_urlopen, mock_version_object):
    """Test precheck to validate error thrown on a Non-200 response from s3"""
    mock_version_object.return_value = self.mock_version
    mock_s3_response = Mock(name='mock s3 response')
    mock_s3_response.getcode.return_value = 404
    mock_urlopen.return_value = mock_s3_response
    with self.assertRaises(IOError):
      ef_version.precheck_dist_hash(self)

  @patch('ef_version.Version')
  @patch('urllib2.urlopen')
  def test_precheck_dist_hash_urllib_error(self, mock_urlopen, mock_version_object):
    """Test preckek to validate error thrown on url error"""
    mock_version_object.return_value = self.mock_version
    mock_s3_response = Mock(name='mock s3 response')
    mock_urlopen.return_value = mock_s3_response
    mock_urlopen.side_effect = IOError
    with self.assertRaises(IOError):
      ef_version.precheck_dist_hash(self)

  @patch('ef_version.Version')
  def test_precheck_dist_hash_version_none(self, mock_version_object):
    """Test precheck_dist_hash when current version is none"""
    response = {"Error": {"Code": "NoSuchKey"}}
    mock_version_object.side_effect = ClientError(response, "Get Object")
    self.assertTrue(ef_version.precheck_dist_hash(self))


class TestVersion(unittest.TestCase):

    def test_version_init(self):

        version_body = StringIO.StringIO("ami-0f24a2bf2a5fb4090")

        version_id = "a8Hwa86edlxkc24HLI_FvCp5J4eJZerK"
        last_modified = datetime.datetime(2018, 11, 6, 6, 10, 4, tzinfo=tzutc())

        version_attrs = {
            'build_number': "43",
            'commit_hash': "0f24a2bf2a5fb4090",
            'location': "in space",
            'last_modified': last_modified.strftime("%Y-%m-%dT%H:%M:%S%Z"),
            'modified_by': "random_dud",
            'status': "destabilized",
            'value': version_body.getvalue()}

        object_version = {
            "AcceptRanges": "bytes",
            "ContentType": "binary/octet-stream",
            "LastModified": last_modified,
            "ContentLength": 21,
            "ContentEncoding": "utf-8",
            "VersionId": version_id,
            "ETag": "\"8c6a54dc6a1c907f7664f11a7b369d7b\"",
            "Metadata": {
                "ef-location": version_attrs["location"],
                "ef-version-status": version_attrs["status"],
                "ef-buildnumber": version_attrs["build_number"],
                "ef-commithash": version_attrs["commit_hash"],
                "ef-modifiedby": version_attrs["modified_by"]
                },
            "Body": version_body
            }

        version = ef_version.Version(object_version)

        for attr, expected in version_attrs.items():
            actual = getattr(version, attr)
            self.assertEqual(
                expected, actual,
                msg="{attr}: expecting {expected!r}, got {actual!r}".format(**locals()))
