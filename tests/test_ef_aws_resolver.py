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
from ef_config import EFConfig
from ef_context import EFContext
from ef_site_config import EFSiteConfig
from ef_utils import fail, http_get_metadata, whereami


class TestEFAwsResolver(unittest.TestCase):
  """Tests for `ef_aws_resolver.py`."""

  # See if I can get rid of this?
  # _context = EFContext()
  # _context.env = "test"

  # # initialize based on where running
  # where = whereami()
  # if where == "local":
  #   session = boto3.Session(profile_name=context.account_alias, region_name=EFConfig.DEFAULT_REGION)
  # elif where == "ec2":
  #   region = http_get_metadata("placement/availability-zone/")
  #   region = region[:-1]
  #   session = boto3.Session(region_name=region)
  # else:
  #   fail("Can't test in environment: " + where)

  # session = boto3.Session(profile_name="default", region_name="us-west-2")
  # _clients = {
  #   "cloudformation": session.client("cloudformation"),
  #   "cloudfront": session.client("cloudfront"),
  #   "ec2": session.client("ec2"),
  #   "iam": session.client("iam"),
  #   "route53": session.client("route53"),
  #   "waf": session.client("waf"),
  #   "SESSION": session
  # }

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

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_network_interface_id = "eni-0011"
    target_description = "target_description"
    network_interfaces_response = {
      "NetworkInterfaces": [
        {
          "NetworkInterfaceId": target_network_interface_id,
          "Description": target_description
        }
      ]
    }
    self._clients["ec2"].describe_network_interfaces.return_value = network_interfaces_response
    lookup_token = "ec2:eni/eni-id," + target_description
    resolver = EFAwsResolver(self._clients)
    result = resolver.lookup(lookup_token)
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
    lookup_token = "ec2:eni/eni-id,no_matching_description"
    resolver = EFAwsResolver(self._clients)
    result = resolver.lookup(lookup_token)
    self.assertIsNone(result)

  def test_ec2_route_table_main_route_table_id(self):
    """Does ec2:route-table/main-route-table-id,vpc-<env> resolve to route table ID"""
    test_string = "ec2:route-table/main-route-table-id,vpc-"+context.env
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^rtb-[a-f0-9]{8}$")

  def test_ec2_route_table_main_route_table_id_none(self):
    """Does ec2:route-table/main-route-table-id,cant_possibly_match return None"""
    test_string = "ec2:route-table/main-route-table-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_ec2_route_table_main_route_table_id_default(self):
    """Does ec2:route-table/main-route-table-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "ec2:route-table/main-route-table-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_ec2_security_group_security_group_id(self):
    """Does ec2:security-group/security-group-id,staging-core-ec2 resolve to a security group id"""
    test_string = "ec2:security-group/security-group-id,staging-core-ec2"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^sg-[a-f0-9]{8}$")

  def test_ec2_security_group_security_group_id_none(self):
    """Does ec2:security-group/security-group-id,cant_possibly_match return None"""
    test_string = "ec2:security-group/security-group-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_ec2_security_group_security_group_id_default(self):
    """Does ec2:security-group/security-group-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "ec2:security-group/security-group-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_ec2_subnet_subnet_id(self):
    """Does ec2:subnet/subnet-id,subnet-staging-a resolve to a subnet ID"""
    test_string = "ec2:subnet/subnet-id,subnet-staging-a"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^subnet-[a-f0-9]{8}$")

  def test_ec2_subnet_subnet_id_none(self):
    """Does ec2:subnet/subnet-id,cant_possibly_match return None"""
    test_string = "ec2:subnet/subnet-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_ec2_subnet_subnet_id_default(self):
    """Does ec2:subnet/subnet-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "ec2:subnet/subnet-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_ec2_vpc_availabilityzones(self):
    """Does ec2:vpc/availabilityzones,vpc-staging resolve to correctly-delimited string of AZ(s)"""
    test_string = "ec2:vpc/availabilityzones,vpc-staging"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^us-west-2(a|b)(\", \"us-west-2(a|b)){0,1}$")

  def test_ec2_vpc_availabilityzones_none(self):
    """Does ec2:vpc/availabilityzones,cant_possibly_match return None"""
    test_string = "ec2:vpc/availabilityzones,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_ec2_vpc_availabilityzones_default(self):
    """Does ec2:vpc/availabilityzones,cant_possibly_match,DEFAULT return default value"""
    test_string = "ec2:vpc/availabilityzones,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_ec2_vpc_cidrblock(self):
    """Does ec2:vpc/cidrblock,vpc-staging resolve to a CIDR block"""
    test_string = "ec2:vpc/cidrblock,vpc-staging"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{2}$")

  def test_ec2_vpc_cidrblock_none(self):
    """Does ec2:vpc/cidrblock,cant_possibly_match return None"""
    test_string = "ec2:vpc/cidrblock,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_ec2_vpc_cidrblock_default(self):
    """Does ec2:vpc/cidrblock,cant_possibly_match,DEFAULT return default value"""
    test_string = "ec2:vpc/cidrblock,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_ec2_vpc_subnets(self):
    """Does ec2:vpc/subnets,vpc-staging resolve to correctly-delimited string of AZ(s)"""
    test_string = "ec2:vpc/subnets,vpc-staging"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^subnet-[a-f0-9]{8}(\", \"subnet-[a-f0-9]{8}){0,1}$")

  def test_ec2_vpc_subnets_none(self):
    """Does ec2:vpc/subnets,cant_possibly_match return None"""
    test_string = "ec2:vpc/subnets,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_ec2_vpc_subnets_default(self):
    """Does ec2:vpc/subnets,cant_possibly_match,DEFAULT return default value"""
    test_string = "ec2:vpc/subnets,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_ec2_vpc_vpc_id(self):
    """Does ec2:vpc/vpc-id,vpc-staging resolve to VPC ID"""
    test_string = "ec2:vpc/vpc-id,vpc-staging"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^vpc-[a-f0-9]{8}$")

  def test_ec2_vpc_vpc_id_none(self):
    """Does ec2:vpc/vpc-id,cant_possibly_match return None"""
    test_string = "ec2:vpc/vpc-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_ec2_vpc_vpc_id_default(self):
    """Does ec2:vpc/vpc-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "ec2:vpc/vpc-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_waf_rule_id(self):
    """Does waf:rule-id,global-OfficeCidr resolve to WAF ID"""
    test_string = "waf:rule-id,global-OfficeCidr"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string),
                             "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")

  def test_waf_rule_id_none(self):
    """Does waf:rule-id,cant_possibly_match return None"""
    test_string = "waf:rule-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_waf_rule_id_default(self):
    """Does waf:rule-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "waf:rule-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_waf_web_acl_id(self):
    """Does waf:web-acl-id,staging-StaticAcl resolve to Web ACL ID"""
    test_string = "waf:web-acl-id,staging-StaticAcl"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string),
                             "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")

  def test_waf_web_acl_id_none(self):
    """Does waf:web-acl-id,cant_possibly_match return None"""
    test_string = "waf:web-acl-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_waf_web_acl_id_default(self):
    """Does waf:web-acl-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "waf:web-acl-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_route53_private_hosted_zone_id(self):
    """Does route53:private-hosted-zone-id,cx-proto0.com. resolve to zone ID"""
    test_string = "route53:private-hosted-zone-id,cx-proto0.com."
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^[A-Z0-9]{13,14}$")

  def test_route53_private_hosted_zone_id_none(self):
    """Does route53:private-hosted-zone-id,cant_possibly_match return None"""
    test_string = "route53:private-hosted-zone-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_route53_private_hosted_zone_id_default(self):
    """Does route53:private-hosted-zone-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "route53:private-hosted-zone-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_route53_public_hosted_zone_id(self):
    """Does route53:hosted-zone-id,cx-proto0.com. resolve to zone ID"""
    test_string = "route53:public-hosted-zone-id,cx-proto0.com."
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^[A-Z0-9]{13,14}$")

  def test_route53_public_hosted_zone_id_none(self):
    """Does route53:public-hosted-zone-id,cant_possibly_match return None"""
    test_string = "route53:public-hosted-zone-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_route53_public_hosted_zone_id_default(self):
    """Does route53:public-hosted-zone-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "route53:public-hosted-zone-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

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
