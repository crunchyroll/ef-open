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

from mock import call, Mock, patch

# For local application imports, context_paths must be first despite lexicon ordering
import context_paths

from crf_version_resolver import CRFVersionResolver


class TestCRFVersionResolver(unittest.TestCase):
  """Tests for 'crf_version_resolver.py'"""

  def setUp(self):
    """
    Setup function that is run before every test

    Returns:
      None
    """
    mock_ec2_client = Mock(name="Mock EC2 Client")
    mock_s3_client = Mock(name="Mock S3 Client")

    self._clients = {
      "ec2": mock_ec2_client,
      "s3": mock_s3_client
    }

  def tearDown(self):
    """
    Teardown function that is run after every test.

    Returns:
      None
    """
    pass

  @patch('crf_version_resolver.CRFVersionResolver._s3_get')
  def test_ami_id(self, mock_s3_get):
    """Does ami-id,proto0/test-instance resolve to an AMI id"""
    mock_s3_get.return_value = 'ami-12345678'
    test_string = "ami-id,proto0/test-instance"
    resolver = CRFVersionResolver(self._clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^ami-[a-f0-9]{8}$")
