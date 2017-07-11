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

import boto3
from mock import call, Mock, patch

# For local application imports, context_paths must be first despite lexicon ordering
import context_paths
from ef_aws_resolver import EFAwsResolver


class TestEFAwsResolver(unittest.TestCase):
  """Tests for `ef_aws_resolver.py`."""

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
    mock_route_53_client = Mock(name="Mock Route 53 Client")
    mock_waf_client = Mock(name="Mock WAF Client")
    mock_session = Mock(name="Mock Client")

    self._clients = {
      "cloudformation": mock_cloud_formation_client,
      "cloudfront": mock_cloud_front_client,
      "ec2": mock_ec2_client,
      "iam": mock_iam_client,
      "route53": mock_route_53_client,
      "waf": mock_waf_client,
      "SESSION": mock_session
    }

    # session = boto3.Session(profile_name="default", region_name="us-west-2")
    # self._clients = {
    #   "cloudformation": session.client("cloudformation"),
    #   "cloudfront": session.client("cloudfront"),
    #   "ec2": session.client("ec2"),
    #   "iam": session.client("iam"),
    #   "route53": session.client("route53"),
    #   "waf": session.client("waf"),
    #   "SESSION": session
    # }

  def tearDown(self):
    """
    Teardown function that is run after every test.

    Returns:
      None
    """
    pass

  def test_acm_certificate_arn(self):
    """
    Tests acm_certificate_arn regular success case in obtaining the target certificate

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_certificate_arn = "arn:aws:acm:us-west-2:111000:certificate/target_cert"
    target_domain_name = "second.com"
    lookup_token = "acm:certificate-arn,us-west-2/" + target_domain_name
    mock_acm_client = Mock(name="Mock ACM Client")
    mock_acm_client.list_certificates.return_value = {
      "CertificateSummaryList": [
        {
          "CertificateArn": "arn:aws:acm:us-west-2:111000:certificate/not_target_cert",
          "DomainName": "first.com"
        },
        {
          "CertificateArn": target_certificate_arn,
          "DomainName": target_domain_name
        }
      ]
    }
    target_certificate = {
      "Certificate": {
        "IssuedAt": 1472845485.0,
        "DomainName": target_domain_name,
        "CertificateArn": target_certificate_arn
      }
    }

    mock_acm_client.describe_certificate.side_effect = [target_certificate]
    self._clients["SESSION"].client.return_value = mock_acm_client
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup(lookup_token)
    self.assertEquals(result_certificate_arn, target_certificate_arn)

  def test_acm_certificate_arn_multiple_matching_certificates(self):
    """
    Tests acm_certificate_arn to see if it can obtain the target certificate with the latest IssuedAt when there are
    multiple certificates with the same domain name.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_certificate_arn = "arn:aws:acm:us-west-2:111000:certificate/target_cert"
    target_domain_name = "second.com"
    lookup_token = "acm:certificate-arn,us-west-2/" + target_domain_name
    mock_acm_client = Mock(name="Mock ACM Client")
    mock_acm_client.list_certificates.return_value = {
      "CertificateSummaryList": [
        {
          "CertificateArn": "arn:aws:acm:us-west-2:111000:certificate/not_target_cert",
          "DomainName": "first.com"
        },
        {
          "CertificateArn": target_certificate_arn,
          "DomainName": target_domain_name
        },
        {
          "CertificateArn": target_certificate_arn,
          "DomainName": target_domain_name
        }
      ]
    }
    old_certificate = {
      "Certificate": {
        "IssuedAt": 1472845000.0,
        "DomainName": target_domain_name,
        "CertificateArn": "arn:aws:acm:us-west-2:111000:certificate/older_target_cert"
      }
    }
    target_certificate = {
      "Certificate": {
        "IssuedAt": 1472845485.0,
        "DomainName": target_domain_name,
        "CertificateArn": target_certificate_arn
      }
    }
    mock_acm_client.describe_certificate.side_effect = [old_certificate, target_certificate]
    self._clients["SESSION"].client.return_value = mock_acm_client
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup(lookup_token)
    self.assertEquals(result_certificate_arn, target_certificate_arn)

  def test_acm_certificate_arn_bad_input(self):
    """
    Tests acm_certificate_arn with bad inputs, ones that would not be caught by lookup.

    Returns:
      None

    Raises
      AssertionError if any of the assert checks fail
    """
    lookup_token = "acm:certificate-arn,junk_value"
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup(lookup_token)
    self.assertIsNone(result_certificate_arn)

    lookup_token = "acm:certificate-arn,None"
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup(lookup_token)
    self.assertIsNone(result_certificate_arn)

    lookup_token = "acm:certificate-arn,"
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup(lookup_token)
    self.assertIsNone(result_certificate_arn)

  def test_acm_certificate_arn_no_certificates(self):
    """
    Test acm_certificate_arn to see if it returns None when no certificates are found.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_domain_name = "second.com"
    lookup_token = "acm:certificate-arn,us-west-2/" + target_domain_name
    mock_acm_client = Mock(name="Mock ACM Client")
    mock_acm_client.list_certificates.return_value = {"CertificateSummaryList": []}
    self._clients["SESSION"].client.return_value = mock_acm_client
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup(lookup_token)
    self.assertEquals(result_certificate_arn, None)

  def test_acm_certificate_arn_old_matching_certificate_has_no_issued_date(self):
    """
    Tests acm_certificate_arn to see if it returns correct target certificate arn when the older
    matching certificate has no matching DateIssued.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_certificate_arn = "arn:aws:acm:us-west-2:111000:certificate/target_cert"
    target_domain_name = "second.com"
    lookup_token = "acm:certificate-arn,us-west-2/" + target_domain_name
    mock_acm_client = Mock(name="Mock ACM Client")
    mock_acm_client.list_certificates.return_value = {
      "CertificateSummaryList": [
        {
          "CertificateArn": "arn:aws:acm:us-west-2:111000:certificate/not_target_cert",
          "DomainName": "first.com"
        },
        {
          "CertificateArn": target_certificate_arn,
          "DomainName": target_domain_name
        },
        {
          "CertificateArn": target_certificate_arn,
          "DomainName": target_domain_name
        }
      ]
    }
    old_certificate = {
      "Certificate": {
        "DomainName": target_domain_name,
        "CertificateArn": "arn:aws:acm:us-west-2:111000:certificate/older_target_cert"
      }
    }
    target_certificate = {
      "Certificate": {
        "IssuedAt": 1472845485.0,
        "DomainName": target_domain_name,
        "CertificateArn": target_certificate_arn
      }
    }
    mock_acm_client.describe_certificate.side_effect = [old_certificate, target_certificate]
    self._clients["SESSION"].client.return_value = mock_acm_client
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup(lookup_token)
    self.assertEquals(result_certificate_arn, target_certificate_arn)

  def test_acm_certificate_arn_target_certificate_has_no_issued_date(self):
    """
    Tests acm_certificate_arn to see if target certificate is returned even when it has no date issued.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_certificate_arn = "arn:aws:acm:us-west-2:111000:certificate/target_cert"
    target_domain_name = "second.com"
    lookup_token = "acm:certificate-arn,us-west-2/" + target_domain_name
    mock_acm_client = Mock(name="Mock ACM Client")
    mock_acm_client.list_certificates.return_value = {
      "CertificateSummaryList": [
        {
          "CertificateArn": "arn:aws:acm:us-west-2:111000:certificate/not_target_cert",
          "DomainName": "first.com"
        },
        {
          "CertificateArn": target_certificate_arn,
          "DomainName": target_domain_name
        },
        {
          "CertificateArn": target_certificate_arn,
          "DomainName": target_domain_name
        }
      ]
    }
    old_certificate = {
      "Certificate": {
        "IssuedAt": 1472845000.0,
        "DomainName": target_domain_name,
        "CertificateArn": "arn:aws:acm:us-west-2:111000:certificate/older_target_cert"
      }
    }
    target_certificate = {
      "Certificate": {
        "DomainName": target_domain_name,
        "CertificateArn": target_certificate_arn
      }
    }
    mock_acm_client.describe_certificate.side_effect = [old_certificate, target_certificate]
    self._clients["SESSION"].client.return_value = mock_acm_client
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup(lookup_token)
    self.assertEquals(result_certificate_arn, target_certificate_arn)

  @patch('ef_aws_resolver.EFAwsResolver.ec2_elasticip_elasticip_ipaddress')
  def test_ec2_elasticip_elasticip_id(self, mock_ec2_elasticip_elasticip_ipaddress):
    """
    Tests ec2_elasticip_elasticip_id to see if it returns an id given a valid input.
    Example input: ec2:elasticip/elasticip-id,ElasticIpDevVideo1

    Args:
      mock_ec2_elasticip_elasticip_ipaddress: MagicMock, returns back an ip address

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_ec2_elasticip_elasticip_ipaddress.return_value = "1.2.3.4"
    allocation_id = "eipalloc-abc123"
    self._clients["ec2"].describe_addresses.return_value = {
      "Addresses": [
        {
          "AllocationId": allocation_id
        }
      ]
    }

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:elasticip/elasticip-id,ElasticIpEnvironmentService1")
    self.assertEquals(allocation_id, result)


  def test_ec2_elasticip_elasticip_id_bad_input(self):
    """
    Tests ec2_elasticip_elasticip_id to see if it returns None with bad input

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:elasticip/elasticip-id,cant_possibly_match")
    self.assertIsNone(result)

  def test_ec2_elasticip_elasticip_ipaddress(self):
    """
    Tests ec2_elastic_elasticip_ipaddress to see if it returns an ip address given a valid input
    Example input: ec2:elasticip/elasticip-ipaddress,ElasticIpDevVideo1

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    ip_address = "10.0.0.333"
    self._clients["cloudformation"].describe_stack_resources.return_value = {
      "StackResources": [
        {
            "PhysicalResourceId": ip_address
        }
      ]
    }
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:elasticip/elasticip-ipaddress,ElasticIpEnvironmentService1")
    self.assertEquals(result, ip_address)

  def test_ec2_elasticip_elasticip_ipaddress_bad_input(self):
    """
    Tests ec2_elasticip_elasticip_ipaddress in that it returns None when given bad inputs

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:elasticip/elasticip-ipaddress,cant_possibly_match")
    self.assertIsNone(result)

  def test_ec2_eni_eni_id(self):
    """
    Tests ec2_eni_eni_id to see it returns back a network interface id based on description given
    Example Input: ec2:eni/eni-id,some_description

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_network_interface_id = "eni-0011"
    network_interfaces_response = {
      "NetworkInterfaces": [
        {
          "NetworkInterfaceId": target_network_interface_id,
        }
      ]
    }
    self._clients["ec2"].describe_network_interfaces.return_value = network_interfaces_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:eni/eni-id,target_description")
    self.assertEquals(target_network_interface_id, result)

  def test_ec2_eni_eni_id_no_match(self):
    """
    Tests ec2_eni_eni_id returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    network_interfaces_response = {
      "NetworkInterfaces": []
    }
    self._clients["ec2"].describe_network_interfaces.return_value = network_interfaces_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:eni/eni-id,no_matching_description")
    self.assertIsNone(result)

  def test_ec2_security_group_security_group_id(self):
    """
    Tests ec2_security_group_security_group_id to see if it returns a security group id based on group name.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_security_group_id = "sg-0011"
    security_group_response = {
      "SecurityGroups": [
        {
          "GroupId": target_security_group_id
        }
      ]
    }
    self._clients["ec2"].describe_security_groups.return_value = security_group_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:security-group/security-group-id,my_security_group")
    self.assertEquals(target_security_group_id, result)

  def test_ec2_security_group_security_group_id_no_match(self):
    """
    Tests ec2_security_group_security_group_id to see if it returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    security_group_response = {
      "SecurityGroups": []
    }
    self._clients["ec2"].describe_security_groups.return_value = security_group_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:security-group/security-group-id,cant_possibly_match")
    self.assertIsNone(result)

  def test_ec2_subnet_subnet_id(self):
    """
    Tests ec2_subnet_subnet_id to see if it returns a subnet ID based on matching subnet name in tag

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_subnet_id = "subnet-0011"
    subnet_response = {
      "Subnets": [
        {
          "SubnetId": target_subnet_id
        }
      ]
    }
    self._clients["ec2"].describe_subnets.return_value = subnet_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:subnet/subnet-id,target_subnet_name")
    self.assertEquals(target_subnet_id, result)

  def test_ec2_subnet_subnet_id_no_match(self):
    """
    Tests ec2_subnet_subnet_id to see if it returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    subnet_response = {
      "Subnets": []
    }
    self._clients["ec2"].describe_subnets.return_value = subnet_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:subnet/subnet-id,cant_possibly_match")
    self.assertIsNone(result)

  @patch('ef_aws_resolver.EFAwsResolver.ec2_vpc_vpc_id')
  def test_ec2_vpc_availabilityzones(self, mock_ec2_vpc_vpc_id):
    """
    Tests ec2_vpc_availabilityzones to see if it returns the correct availability zone based on matching vpc name
    in tag

    Args:
      mock_ec2_vpc_vpc_id: MagicMock, returns mock vpc id

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_ec2_vpc_vpc_id.return_value = 'mock_vpc_id'
    target_availability_zone = "us-west-2a"
    availabilityzones_response = {
      "Subnets": [
          {
            "AvailabilityZone": target_availability_zone
          }
      ]
    }
    self._clients["ec2"].describe_subnets.return_value = availabilityzones_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc/availabilityzones,target_subnet_name")
    self.assertEquals(target_availability_zone, result)

  @patch('ef_aws_resolver.EFAwsResolver.ec2_vpc_vpc_id')
  def test_ec2_vpc_availabilityzones_no_vpc_id(self, mock_ec2_vpc_vpc_id):
    """
    Tests ec2_vpc_availabilityzones to see if it returns None when no vpc_id is returned for vpc name in tag

    Args:
      mock_ec2_vpc_vpc_id: MagicMock, returns None

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_ec2_vpc_vpc_id.return_value = None
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc/availabilityzones,target_subnet_name")
    self.assertIsNone(result)

  @patch('ef_aws_resolver.EFAwsResolver.ec2_vpc_vpc_id')
  def test_ec2_vpc_availabilityzones_no_match(self, mock_ec2_vpc_vpc_id):
    """
    Tests ec2_vpc_availabilityzones to see if it returns None when no match is found

    Args:
      mock_ec2_vpc_vpc_id: MagicMock, returns mock vpc id

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_ec2_vpc_vpc_id.return_value = 'mock_vpc_id'
    availabilityzones_response = {
      "Subnets": []
    }
    self._clients["ec2"].describe_subnets.return_value = availabilityzones_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc/availabilityzones,cant_possibly_match")
    self.assertIsNone(result)

  @patch('ef_aws_resolver.EFAwsResolver.ec2_vpc_vpc_id')
  def test_ec2_vpc_subnets(self, mock_ec2_vpc_vpc_id):
    """
    Tests ec2_vpc_subnets to see if it returns the correct subnet id based on matching vpc name in tag

    Args:
      mock_ec2_vpc_vpc_id: MagicMock, returns mock vpc id

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_subnet_id = "subnet-9c2ea7ea"
    mock_ec2_vpc_vpc_id.return_value = 'mock_vpc_id'
    subnets_response = {
      "Subnets": [
        {
          "SubnetId": target_subnet_id
        }
      ]
    }
    self._clients["ec2"].describe_subnets.return_value = subnets_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc/subnets,target_subnet_name")
    self.assertEquals(target_subnet_id, result)

  @patch('ef_aws_resolver.EFAwsResolver.ec2_vpc_vpc_id')
  def test_ec2_vpc_subnets_no_match(self, mock_ec2_vpc_vpc_id):
    """
    Tests ec2_vpc_subnets to see if returns None when there are no matches

    Args:
      mock_ec2_vpc_vpc_id: MagicMock, returns mock vpc id

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_ec2_vpc_vpc_id.return_value = 'mock_vpc_id'
    availabilityzones_response = {
      "Subnets": []
    }
    self._clients["ec2"].describe_subnets.return_value = availabilityzones_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc/subnets,cant_possibly_match")
    self.assertIsNone(result)

  def test_ec2_vpc_cidrblock(self):
    """
    Tests ec2_vpc_cidrblock to see if it returns the target cidr block given vpc name in tag

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_cidr_block = "10.20.128.0/18"
    vpc_response = {
      "Vpcs": [
        {
          "CidrBlock": target_cidr_block
        }
      ]
    }
    self._clients["ec2"].describe_vpcs.return_value = vpc_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc/cidrblock,target_vpc_name")
    self.assertEquals(target_cidr_block, result)

  def test_ec2_vpc_cidrblock_no_match(self):
    """
    Tests ec2_vpc_cidrblock to see if it returns None when no match is found

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    vpc_response = {
      "Vpcs": []
    }
    self._clients["ec2"].describe_vpcs.return_value = vpc_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc/cidrblock,cant_possibly_match")
    self.assertIsNone(result)

  def test_ec2_vpc_vpc_id(self):
    """
    Tests ec2_vpc_vpc_id to see if it returns vpc id based on matching vpc name in tag

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_vpc_id = "vpc-0011"
    vpc_response = {
      "Vpcs": [
        {
          "VpcId": target_vpc_id
        }
      ]
    }
    self._clients["ec2"].describe_vpcs.return_value = vpc_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc/vpc-id,target_vpc_name")
    self.assertEquals(target_vpc_id, result)

  def test_ec2_vpc_vpc_id_none(self):
    """
    Tests ec2_vpc_vpc_id to see if it returns None when no match is found

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    vpc_response = {
      "Vpcs": []
    }
    self._clients["ec2"].describe_vpcs.return_value = vpc_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc/vpc-id,target_vpc_name")
    self.assertIsNone(result)

  def test_waf_rule_id(self):
    """
    Tests waf_rule_id to see if it returns the rule id that matches the rule name

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_rule_id = "55-66"
    rules_response = {
      "Rules": [
        {
          "Name": "rule_1",
          "RuleId": "11-22"
        },
        {
          "Name": "rule_2",
          "RuleId": "33-44"
        },
        {
          "Name": "rule_3",
          "RuleId": target_rule_id
        }
      ]
    }
    self._clients["waf"].list_rules.return_value = rules_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("waf:rule-id,rule_3")
    self.assertEquals(target_rule_id, result)

  def test_waf_rule_id_more_rules_than_limit(self):
    """
    Tests waf_rule_id to see if it returns the rule id that matches the rule name where there are more rules
    than the limit, thus the NextMarker

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_rule_name = "rule_4"
    target_rule_id = "77-88"
    first_rules_response = {
      "Rules": [
        {
          "Name": "rule_1",
          "RuleId": "11-22"
        },
        {
          "Name": "rule_2",
          "RuleId": "33-44"
        },
      ],
      "NextMarker": "112233"
    }
    second_rules_response = {
      "Rules": [
        {
          "Name": "rule_3",
          "RuleId": "55-66"
        },
        {
          "Name": target_rule_name,
          "RuleId": target_rule_id
        }
      ]
    }
    self._clients["waf"].list_rules.side_effect = [first_rules_response, second_rules_response]
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("waf:rule-id," + target_rule_name)
    self.assertEquals(target_rule_id, result)

  def test_waf_rule_id_no_match(self):
    """
    Tests waf_rule_id to see if it returns when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    rules_response = {
      "Rules": [
        {
          "Name": "rule_1",
          "RuleId": "11-22"
        },
        {
          "Name": "rule_2",
          "RuleId": "33-44"
        },
        {
          "Name": "rule_3",
          "RuleId": "55-66"
        }
      ]
    }
    self._clients["waf"].list_rules.return_value = rules_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("waf:rule-id,rule_4")
    self.assertIsNone(result)

    rules_response = {
      "Rules": []
    }
    self._clients["waf"].list_rules.return_value = rules_response
    result = ef_aws_resolver.lookup("waf:rule-id,rule4")
    self.assertIsNone(result)

  def test_waf_web_acl_id(self):
    """
    Tests waf_web_acl_id to see if it returns the correct web acl id based on given web acl name

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_web_acl_id = "55-66"
    web_acls_response = {
      "WebACLs": [
        {
          "WebACLId": "11-22",
          "Name": "first_web_acl"
        },
        {
          "WebACLId": "33-44",
          "Name": "second_web_acl"
        },
        {
          "WebACLId": target_web_acl_id,
          "Name": "third_web_acl"
        }
      ]
    }
    self._clients["waf"].list_web_acls.return_value = web_acls_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("waf:web-acl-id,third_web_acl")
    self.assertEquals(target_web_acl_id, result)

  def test_waf_web_acl_id_more_web_acls_than_limit(self):
    """
    Tests waf_web_acl_id to see if returns the correct web acl id if the number of waf web acl results is greater than
    the limit, thus the NextMarker

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_web_acl_name = "fourth_web_acl"
    target_web_acl_id = "77-88"
    first_web_acls_response = {
      "WebACLs": [
        {
          "WebACLId": "11-22",
          "Name": "first_web_acl"
        },
        {
          "WebACLId": "33-44",
          "Name": "second_web_acl"
        }
      ],
      "NextMarker": "112233"
    }
    second_web_acls_response = {
      "WebACLs": [
        {
          "WebACLId": "55-66",
          "Name": "third_web_acl"
        },
        {
          "WebACLId": target_web_acl_id,
          "Name": target_web_acl_name
        }
      ]
    }
    self._clients["waf"].list_web_acls.side_effect = [first_web_acls_response, second_web_acls_response]
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("waf:web-acl-id," + target_web_acl_name)
    self.assertEquals(target_web_acl_id, result)

  def test_waf_web_acl_id_no_match(self):
    """
    Tests waf_web_acl_id to see if returns None if there are no matches

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    web_acls_response = {
      "WebACLs": [
        {
          "WebACLId": "11-22",
          "Name": "first_web_acl"
        },
        {
          "WebACLId": "33-44",
          "Name": "second_web_acl"
        },
        {
          "WebACLId": "55-66",
          "Name": "third_web_acl"
        }
      ]
    }
    self._clients["waf"].list_web_acls.return_value = web_acls_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("waf:web-acl-id,cant_possibly_match")
    self.assertIsNone(result)

    web_acls_response = {
      "WebACLs": []
    }
    self._clients["waf"].list_web_acls.return_value = web_acls_response
    result = ef_aws_resolver.lookup("waf:web-acl-id,cant_possibly_match")
    self.assertIsNone(result)

  def test_route53_public_hosted_zone_id(self):
    """
    Tests route53_public_hosted_zone_id to see if it returns the hosted zone Id given the domain name and if the
    hosted zone is not private

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_hosted_zone_id = "112233"
    target_hosted_zone_name = "my_domain.com."
    hosted_zones_by_name_response = {
      "HostedZones": [
        {
          "Config": {
              "PrivateZone": True
          },
          "Id": "/hostedzone/1Z2Y3X",
          "Name": "other_domain.com."
        },
        {
          "Config": {
              "PrivateZone": False
          },
          "Id": "/hostedzone/B1C1D1",
          "Name": "other_domain.com."
        },
        {
          "Config": {
              "PrivateZone": True
          },
          "Id": "/hostedzone/AABBCC",
          "Name": target_hosted_zone_name
        },
        {
          "Config": {
            "PrivateZone": False
          },
          "Id": "/hostedzone/" + target_hosted_zone_id,
          "Name": target_hosted_zone_name
        }
      ],
      "IsTruncated": False
    }
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_by_name_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("route53:public-hosted-zone-id," + target_hosted_zone_name)
    self.assertEquals(target_hosted_zone_id, result)

  def test_route53_public_hosted_zone_id_is_truncated(self):
    """
    Tests route53_public_hosted_zone_id to see if it returns the correct hosted zone id for when the results
    returned need to be truncated based on given domain name

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_hosted_zone_id = "112233"
    target_hosted_zone_name = "my_domain.com."
    first_hosted_zones_by_name_response = {
      "HostedZones": [
        {
          "Config": {
            "PrivateZone": True
          },
          "Id": "/hostedzone/1Z2Y3X",
          "Name": "other_domain.com."
        },
        {
          "Config": {
            "PrivateZone": False
          },
          "Id": "/hostedzone/B1C1D1",
          "Name": "other_domain.com."
        }
      ],
      "IsTruncated": True,
      "NextHostedZoneId": "aabbcc"
    }
    second_hosted_zones_by_name_response = {
      "HostedZones": [
        {
          "Config": {
            "PrivateZone": True
          },
          "Id": "/hostedzone/AABBCC",
          "Name": target_hosted_zone_name
        },
        {
          "Config": {
            "PrivateZone": False
          },
          "Id": "/hostedzone/" + target_hosted_zone_id,
          "Name": target_hosted_zone_name
        }
      ],
      "IsTruncated": False
    }
    self._clients["route53"].list_hosted_zones_by_name.side_effect = [first_hosted_zones_by_name_response,
                                                                      second_hosted_zones_by_name_response]
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("route53:public-hosted-zone-id," + target_hosted_zone_name)
    self.assertEquals(target_hosted_zone_id, result)

  def test_route53_public_hosted_zone_id_malformed_domain_name(self):
    """
    Tests route53_public_hosted_zone_id to see if it returns None if the . is missing at the end of the domain name

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("route53:public-hosted-zone-id,malformed_url.com")
    self.assertIsNone(result)

  def test_route53_public_hosted_zone_id_no_match(self):
    """
    Tests route53_public_hosted_zone_id to see if it returns None when there are no matches

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    hosted_zones_by_name_response = {
      "HostedZones": [
        {
          "Config": {
              "PrivateZone": True
          },
          "Id": "/hostedzone/1Z2Y3X",
          "Name": "other_domain.com."
        },
        {
          "Config": {
              "PrivateZone": False
          },
          "Id": "/hostedzone/B1C1D1",
          "Name": "other_domain.com."
        },
        {
          "Config": {
              "PrivateZone": True
          },
          "Id": "/hostedzone/AABBCC",
          "Name": "another_domain.com."
        },
        {
          "Config": {
            "PrivateZone": False
          },
          "Id": "/hostedzone/11223344",
          "Name": "another_domain.com."
        }
      ],
      "IsTruncated": False
    }
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_by_name_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("route53:public-hosted-zone-id,cant_possibly_match.")
    self.assertIsNone(result)

    hosted_zones_by_name_response = {
      "HostedZones": [],
      "IsTruncated": False
    }
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_by_name_response
    result = ef_aws_resolver.lookup("route53:public-hosted-zone-id,cant_possibly_match.")
    self.assertIsNone(result)

  def test_route53_private_hosted_zone_id(self):
    """
    Tests route53_private_hosted_zone_id to see if it returns the correct hosted zone id given the domain name and
    if the hosted zone is private

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_hosted_zone_id = "112233"
    target_hosted_zone_name = "my_domain.com."
    hosted_zones_by_name_response = {
      "HostedZones": [
        {
          "Config": {
            "PrivateZone": True
          },
          "Id": "/hostedzone/1Z2Y3X",
          "Name": "other_domain.com."
        },
        {
          "Config": {
            "PrivateZone": False
          },
          "Id": "/hostedzone/B1C1D1",
          "Name": "other_domain.com."
        },
        {
          "Config": {
            "PrivateZone": False
          },
          "Id": "/hostedzone/AABBCC",
          "Name": target_hosted_zone_name
        },
        {
          "Config": {
            "PrivateZone": True
          },
          "Id": "/hostedzone/" + target_hosted_zone_id,
          "Name": target_hosted_zone_name
        }
      ],
      "IsTruncated": False
    }
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_by_name_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("route53:private-hosted-zone-id," + target_hosted_zone_name)
    self.assertEquals(target_hosted_zone_id, result)

  def test_route53_private_hosted_zone_id_is_truncated(self):
    """
    Tests route53_private_hosted_zone_id to see if it returns the correct hosted zone id if the results are
    truncated based on domain name given

    Returns:
      None
    """
    target_hosted_zone_id = "112233"
    target_hosted_zone_name = "my_domain.com."
    first_hosted_zones_by_name_response = {
      "HostedZones": [
        {
          "Config": {
            "PrivateZone": True
          },
          "Id": "/hostedzone/1Z2Y3X",
          "Name": "other_domain.com."
        },
        {
          "Config": {
            "PrivateZone": False
          },
          "Id": "/hostedzone/B1C1D1",
          "Name": "other_domain.com."
        }
      ],
      "IsTruncated": True,
      "NextHostedZoneId": "aabbcc"
    }
    second_hosted_zones_by_name_response = {
      "HostedZones": [
        {
          "Config": {
            "PrivateZone": False
          },
          "Id": "/hostedzone/AABBCC",
          "Name": target_hosted_zone_name
        },
        {
          "Config": {
            "PrivateZone": True
          },
          "Id": "/hostedzone/" + target_hosted_zone_id,
          "Name": target_hosted_zone_name
        }
      ],
      "IsTruncated": False
    }
    self._clients["route53"].list_hosted_zones_by_name.side_effect = [first_hosted_zones_by_name_response,
                                                                      second_hosted_zones_by_name_response]
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("route53:private-hosted-zone-id," + target_hosted_zone_name)
    self.assertEquals(target_hosted_zone_id, result)

  def test_route53_private_hosted_zone_id_malformed_domain_name(self):
    """
    Tests route53_private_hosted_zone_id to see if it returns None when the . is missing at the end of the domain name

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("route53:private-hosted-zone-id,malformed_url.com")
    self.assertIsNone(result)

  def test_route53_private_hosted_zone_id_no_match(self):
    """
    Tests route53_private_hosted_zone_id to see if it returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    hosted_zones_by_name_response = {
      "HostedZones": [
        {
          "Config": {
            "PrivateZone": True
          },
          "Id": "/hostedzone/1Z2Y3X",
          "Name": "other_domain.com."
        },
        {
          "Config": {
            "PrivateZone": False
          },
          "Id": "/hostedzone/B1C1D1",
          "Name": "other_domain.com."
        },
        {
          "Config": {
            "PrivateZone": True
          },
          "Id": "/hostedzone/AABBCC",
          "Name": "another_domain.com."
        },
        {
          "Config": {
            "PrivateZone": False
          },
          "Id": "/hostedzone/11223344",
          "Name": "another_domain.com."
        }
      ],
      "IsTruncated": False
    }
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_by_name_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("route53:private-hosted-zone-id,cant_possibly_match.")
    self.assertIsNone(result)

    hosted_zones_by_name_response = {
      "HostedZones": [],
      "IsTruncated": False
    }
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_by_name_response
    result = ef_aws_resolver.lookup("route53:private-hosted-zone-id,cant_possibly_match.")
    self.assertIsNone(result)

  @patch('ef_aws_resolver.EFAwsResolver.ec2_vpc_vpc_id')
  def test_ec2_route_table_main_route_table_id(self, mock_ec2_vpc_vpc_id):
    """
    Tests ec2_route_table_main_route_table_id to see if it returns the correct route table id based on vpc name

    Args:
      mock_ec2_vpc_vpc_id: MagicMock, returns mock vpc id

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_route_table_id = "rtb-111222"
    mock_ec2_vpc_vpc_id.return_value = "mock_vpc_id"
    route_table_response = {
      "RouteTables": [
        {
          "RouteTableId": target_route_table_id
        }
      ]
    }
    self._clients["ec2"].describe_route_tables.return_value = route_table_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:route-table/main-route-table-id,target_vpc_name")
    self.assertEquals(target_route_table_id, result)

  @patch('ef_aws_resolver.EFAwsResolver.ec2_vpc_vpc_id')
  def test_ec2_route_table_main_route_table_id_no_single_match(self, mock_ec2_vpc_vpc_id):
    """
    Tests ec2_route_table_main_route_table_id to see if it returns None if no matches or more than one match occurs

    Args:
      mock_ec2_vpc_vpc_id: MagicMock, returns mock vpc id

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    mock_ec2_vpc_vpc_id.return_value = "mock_vpc_id"
    route_table_response = {
      "RouteTables": [
        {
          "RouteTableId": "rtb-111222"
        },
        {
          "RouteTableId": "rtb-333444"
        }
      ]
    }
    self._clients["ec2"].describe_route_tables.return_value = route_table_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:route-table/main-route-table-id,target_vpc_name")
    self.assertIsNone(result)

    route_table_response = {
      "RouteTables": []
    }
    self._clients["ec2"].describe_route_tables.return_value = route_table_response
    result = ef_aws_resolver.lookup("ec2:route-table/main-route-table-id,target_vpc_name")
    self.assertIsNone(result)



  def test_cloudfront_domain_name(self):
    """Does cloudfront:domain-name,static.cx-proto0.com resolve to a Cloudfront FQDN"""
    test_string = "cloudfront:domain-name,static.cx-proto0.com"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^[a-z0-9]{13,14}.cloudfront.net$")

  def test_cloudfront_domain_name_none(self):
    """Does cloudfront:domain-name,cant_possibly_match return None"""
    test_string = "cloudfront:domain-name,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_cloudfront_domain_name_default(self):
    """Does cloudfront:domain-name,cant_possibly_match,DEFAULT return default value"""
    test_string = "cloudfront:domain-name,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_cloudfront_origin_access_identity_oai_id(self):
    """Does cloudfront:origin-access-identity/oai-id,static.cx-proto0.com resolve to oai ID"""
    test_string = "cloudfront:origin-access-identity/oai-id,static.cx-proto0.com"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^[A-Z0-9]{13,14}$")

  def test_cloudfront_origin_access_identity_oai_id_none(self):
    """Does cloudfront:origin-access-identity/oai-id,cant_possibly_match return None"""
    test_string = "cloudfront:origin-access-identity/oai-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_cloudfront_origin_access_identity_oai_id_default(self):
    """Does cloudfront:origin-access-identity/oai-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "cloudfront:origin-access-identity/oai-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_cloudfront_origin_access_identity_oai_canonical_user_id(self):
    """Does cloudfront:origin-access-identity/oai-canonical-user-id,static.cx-proto0.com resolve to oai ID"""
    test_string = "cloudfront:origin-access-identity/oai-canonical-user-id,static.cx-proto0.com"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^[a-z0-9]{96}$")

  def test_cloudfront_origin_access_identity_oai_canonical_user_id_none(self):
    """Does cloudfront:origin-access-identity/oai-canonical-user-id,cant_possibly_match return None"""
    test_string = "cloudfront:origin-access-identity/oai-canonical-user-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_cloudfront_origin_access_identity_oai_canonical_user_id_default(self):
    """Does cloudfront:origin-access-identity/oai-canonical-user-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "cloudfront:origin-access-identity/oai-canonical-user-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")


if __name__ == '__main__':
  unittest.main()
