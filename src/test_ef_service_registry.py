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

from ef_service_registry import EFServiceRegistry

class TestEFUtils(unittest.TestCase):
  """Tests for 'ef_service_registry.py'"""

  def test_sr_loads(self):
    """Can the default SR be loaded? (requires a default SR)"""
    sr = EFServiceRegistry( )

  def test_services(self):
    """Does services() return all the services?"""
    sr = EFServiceRegistry(service_registry_file="test_data/test_service_registry_1.json")
    self.assertEqual(len(sr.services()),4)

  def test_services_one_group(self):
    """Does services("fixtures") return only the services in that group?"""
    sr = EFServiceRegistry(service_registry_file="test_data/test_service_registry_1.json")
    self.assertEqual(len(sr.services("fixtures")),0)
    self.assertEqual(len(sr.services("application_services")),1)
    self.assertEqual(len(sr.services("platform_services")),2)

  def test_service_group(self):
    """Does the lookup for the group of a single service work?"""
    sr = EFServiceRegistry(service_registry_file="test_data/test_service_registry_1.json")
    self.assertRegexpMatches(sr.service_group("test-instance-2"),"^platform_services$")

  def test_valid_envs(self):
    """Does valid_envs return correct envs?"""
    sr = EFServiceRegistry(service_registry_file="test_data/test_service_registry_1.json")
    self.assertIn("proto0",sr.valid_envs("test-instance"))
    self.assertIn("staging",sr.valid_envs("test-instance"))
    self.assertIn("mgmt.ellationeng",sr.valid_envs("test-instance"))
    self.assertNotIn("mgmt.ellation",sr.valid_envs("test-instance"))


if __name__ == '__main__':
  unittest.main()
