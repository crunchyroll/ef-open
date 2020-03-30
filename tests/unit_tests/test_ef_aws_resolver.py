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
import unittest
import datetime

from mock import call, Mock, patch
from botocore.exceptions import ClientError

# For local application imports, context_paths must be first despite lexicon ordering
import context_paths
from ef_aws_resolver import EFAwsResolver
from ef_config import EFConfig
from ef_context import EFContext
from ef_utils import fail, http_get_metadata, whereami


class TestEFAwsResolver(unittest.TestCase):
  """
  Unit tests for `ef_aws_resolver.py`.
  """

  def setUp(self):
    """
    Setup function that is run before every test

    Returns:
      None
    """
    mock_cloud_formation_client = Mock(name="Mock CloudFormation Client")
    mock_cloud_front_client = Mock(name="Mock CloudFront Client")
    mock_cognito_identity_client = Mock(name="Mock Cognito Identity Client")
    mock_cognito_idp_client = Mock(name="Mock Cognito IDP Client")
    mock_ec2_client = Mock(name="Mock EC2 Client")
    mock_ecr_client = Mock(name="Mock ECR Client")
    mock_route_53_client = Mock(name="Mock Route 53 Client")
    mock_waf_client = Mock(name="Mock WAF Client")
    mock_session = Mock(name="Mock Client")
    mock_kms_client = Mock(name="Mock KMS Client")
    mock_elbv2_client = Mock(name="Mock ELBV2 Client")
    mock_ram_client = Mock(name="Mock RAM Client")

    self._clients = {
      "cloudformation": mock_cloud_formation_client,
      "cloudfront": mock_cloud_front_client,
      "cognito-identity": mock_cognito_identity_client,
      "cognito-idp": mock_cognito_idp_client,
      "ec2": mock_ec2_client,
      "ecr": mock_ecr_client,
      "route53": mock_route_53_client,
      "waf": mock_waf_client,
      "SESSION": mock_session,
      "kms": mock_kms_client,
      "elbv2": mock_elbv2_client,
      "ram": mock_ram_client
    }

  def tearDown(self):
    """
    Teardown function that is run after every test.

    Returns:
      None
    """
    pass

  _CERTIFICATE_ARN_PREFIX = "arn:aws:acm:us-west-2:111000:certificate/"

  def _generate_certificate_summary_list(self, make_empty=False):
    """
    Generates a generic certificate summary list. Can be filled with dummy certificate summaries or be an empty list.

    Args:
      make_empty: bool

    Returns:
      Dictionary object containing the certificate summary list, mimicking Amazon ACM actual JSON response
    """
    if make_empty:
      certificate_summary_list = {
        "CertificateSummaryList": []
      }
    else:
      certificate_summary_list = {
        "CertificateSummaryList": [
          {
            "CertificateArn": self._CERTIFICATE_ARN_PREFIX + "not_target_cert",
            "DomainName": "first.com"
          },
          {
            "CertificateArn": self._CERTIFICATE_ARN_PREFIX + "not_target_cert",
            "DomainName": "second.com"
          },
          {
            "CertificateArn": self._CERTIFICATE_ARN_PREFIX + "not_target_cert",
            "DomainName": "third.com"
          }
        ]
      }
    return certificate_summary_list

  def _generate_certificate_summary(self, certificate_arn, domain_name):
    """
    Creates a certificate summary from given parameters

    Args:
      certificate_arn: string
      domain_name: string

    Returns:
      Dictionary object of the certificate summary, mimicking Amazon ACM actual JSON response
    """
    certificate_summary = {
      "CertificateArn": certificate_arn,
      "DomainName": domain_name
    }
    return certificate_summary

  def _generate_certificate_description(self, certificate_arn, domain_name, issued_at=None):
    """
    Creates a certificate description from given parameters

    Args:
      certificate_arn: string
      domain_name: string
      issued_at: float

    Returns:
      Dictionary object of a certificate description, mimicking Amazon ACM actual JSON response
    """
    certificate = {
      "Certificate": {
        "CertificateArn": certificate_arn,
        "DomainName": domain_name,
        "IssuedAt": issued_at
      }
    }
    if not issued_at:
      certificate["Certificate"].pop("IssuedAt", None)
    return certificate

  def _insert_cert_summary_into_list(self, target_certificate_summary, certificate_summary_list):
    """
    Appends the target certificate description into the certificate summary list

    Args:
      target_certificate_summary: dictionary object
      certificate_summary_list: dictionary object that contains the CertificateSummaryList array

    Returns:
      None
    """
    if certificate_summary_list and certificate_summary_list.get("CertificateSummaryList", None):
      certificate_summary_list["CertificateSummaryList"].append(target_certificate_summary)

  def test_acm_certificate_arn(self):
    """
    Tests acm_certificate_arn regular success case in obtaining the target certificate

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Designate values of target certificate
    target_certificate_arn = self._CERTIFICATE_ARN_PREFIX + "target_cert"
    target_domain_name = "my_target.com"

    # Generate certificate summary list with target certificate summary in it
    certificate_summary_list = self._generate_certificate_summary_list()
    target_certificate_summary = self._generate_certificate_summary(target_certificate_arn, target_domain_name)
    self._insert_cert_summary_into_list(target_certificate_summary, certificate_summary_list)

    mock_acm_client = Mock(name="Mock ACM Client")
    mock_acm_client.list_certificates.return_value = certificate_summary_list

    # Generate target certificate description
    target_certificate = self._generate_certificate_description(target_certificate_arn, target_domain_name, datetime.datetime(1971, 1, 1, 0, 0))
    mock_acm_client.describe_certificate.return_value = target_certificate

    # Test actual function and assert results
    self._clients["SESSION"].client.return_value = mock_acm_client
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup("acm:certificate-arn,us-west-2/" + target_domain_name)
    self.assertEqual(result_certificate_arn, target_certificate_arn)

  def test_acm_certificate_arn_multiple_matching_certificates(self):
    """
    Tests acm_certificate_arn to see if it can obtain the target certificate with the latest IssuedAt when there are
    multiple certificates with the same domain name.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Designate values of target certificate
    target_certificate_arn = self._CERTIFICATE_ARN_PREFIX + "target_cert"
    target_domain_name = "my_target.com"

    # Designate values of old certificate
    old_certificate_arn = self._CERTIFICATE_ARN_PREFIX + "older_target_cert"

    # Generate certificate summary list with old and target certificate summaries in it
    certificate_summary_list = self._generate_certificate_summary_list()
    old_certificate_summary = self._generate_certificate_summary(self._CERTIFICATE_ARN_PREFIX + "older_target_cert",
                                                                 target_domain_name)
    target_certificate_summary  = self._generate_certificate_summary(target_certificate_arn, target_domain_name)

    self._insert_cert_summary_into_list(old_certificate_summary, certificate_summary_list)
    self._insert_cert_summary_into_list(target_certificate_summary, certificate_summary_list)

    mock_acm_client = Mock(name="Mock ACM Client")
    mock_acm_client.list_certificates.return_value = certificate_summary_list

    # Generate old and target certificate descriptions
    old_certificate_description = self._generate_certificate_description(old_certificate_arn, target_domain_name, datetime.datetime(1970, 1, 1, 0, 0))
    target_certificate_description = self._generate_certificate_description(target_certificate_arn, target_domain_name,
                                                                            datetime.datetime(1971, 1, 1, 0, 0))
    mock_acm_client.describe_certificate.side_effect = [old_certificate_description, target_certificate_description]

    # Test actual function and assert results
    self._clients["SESSION"].client.return_value = mock_acm_client
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup("acm:certificate-arn,us-west-2/" + target_domain_name)
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

  def test_acm_certificate_arn_no_match(self):
    """
    Test acm_certificate_arn to see if it returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Generate a certificate summary list with no target certificate summary
    certificate_summary_list = self._generate_certificate_summary_list()

    mock_acm_client = Mock(name="Mock ACM Client")
    mock_acm_client.list_certificates.return_value = certificate_summary_list

    # Test actual function and assert results
    self._clients["SESSION"].client.return_value = mock_acm_client
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup("acm:certificate-arn,us-west-2/cant_possibly_match")
    self.assertIsNone(result_certificate_arn)

    # Generate an empty certificate summary list
    certificate_summary_list = self._generate_certificate_summary_list(make_empty=True)

    mock_acm_client.list_certificates.return_value = certificate_summary_list

    # Test actual function and assert results
    result_certificate_arn = ef_aws_resolver.lookup("acm:certificate-arn,us-west-2/cant_possibly_match")
    self.assertIsNone(result_certificate_arn)

  def test_acm_certificate_arn_old_matching_certificate_has_no_issued_date(self):
    """
    Tests acm_certificate_arn to see if it returns correct target certificate arn when the older
    matching certificate has no matching DateIssued.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Designate values of target certificate
    target_certificate_arn = self._CERTIFICATE_ARN_PREFIX + "target_cert"
    target_domain_name = "my_target.com"

    # Designate values of old certificate
    old_certificate_arn = self._CERTIFICATE_ARN_PREFIX + "older_target_cert"

    # Generate certificate summary list with old and target certificate summaries in it
    certificate_summary_list = self._generate_certificate_summary_list()
    old_certificate_summary = self._generate_certificate_summary(old_certificate_arn, target_domain_name)
    target_certificate_summary = self._generate_certificate_summary(target_certificate_arn, target_domain_name)
    self._insert_cert_summary_into_list(old_certificate_summary, certificate_summary_list)
    self._insert_cert_summary_into_list(target_certificate_summary, certificate_summary_list)

    mock_acm_client = Mock(name="Mock ACM Client")
    mock_acm_client.list_certificates.return_value = certificate_summary_list

    # Generate old certificate description without issued at date
    old_certificate_description = self._generate_certificate_description(old_certificate_arn, target_domain_name)

    # Generate target certificate description
    target_certificate_description = self._generate_certificate_description(target_certificate_arn, target_domain_name,
                                                                            datetime.datetime(1971, 1, 1, 0, 0))
    mock_acm_client.describe_certificate.side_effect = [old_certificate_description, target_certificate_description]

    # Test actual function and assert results
    self._clients["SESSION"].client.return_value = mock_acm_client
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup("acm:certificate-arn,us-west-2/" + target_domain_name)
    self.assertEquals(result_certificate_arn, target_certificate_arn)

  def test_acm_certificate_arn_target_certificate_has_no_issued_date(self):
    """
    Tests acm_certificate_arn to see if target certificate is returned even when it has no date issued. The older
    target certificate has an issued date.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Designate values of target certificate
    target_certificate_arn = self._CERTIFICATE_ARN_PREFIX + "target_cert"
    target_domain_name = "my_target.com"

    # Designate values of old certificate
    old_certificate_arn = self._CERTIFICATE_ARN_PREFIX + "older_target_cert"

    # Generate certificate summary list with old and target certificate summaries in it
    certificate_summary_list = self._generate_certificate_summary_list()
    old_certificate_summary = self._generate_certificate_summary(old_certificate_arn, target_domain_name)
    target_certificate_summary = self._generate_certificate_summary(target_certificate_arn, target_domain_name)
    self._insert_cert_summary_into_list(old_certificate_summary, certificate_summary_list)
    self._insert_cert_summary_into_list(target_certificate_summary, certificate_summary_list)

    mock_acm_client = Mock(name="Mock ACM Client")
    mock_acm_client.list_certificates.return_value = certificate_summary_list

    # Generate old certificate description with an issued at date
    old_certificate_description = self._generate_certificate_description(old_certificate_arn, target_domain_name, datetime.datetime(1969, 1, 1, 0, 0))

    # Generate target certificate description without issued at date
    target_certificate_description = self._generate_certificate_description(target_certificate_arn, target_domain_name)
    mock_acm_client.describe_certificate.side_effect = [old_certificate_description, target_certificate_description]

    # Test actual function and assert results
    self._clients["SESSION"].client.return_value = mock_acm_client
    ef_aws_resolver = EFAwsResolver(self._clients)
    result_certificate_arn = ef_aws_resolver.lookup("acm:certificate-arn,us-west-2/" + target_domain_name)
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

  def test_ec2_network_network_acl_id(self):
    """
    Tests ec2_network_network_acl_id to see if it returns a network ACL ID based on matching network ACL name in tag

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_network_acl_id = "acl-00000001"
    network_acl_response = {
      "NetworkAcls": [
        {
          "NetworkAclId": target_network_acl_id
        }
      ]
    }
    self._clients["ec2"].describe_network_acls.return_value = network_acl_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:network/network-acl-id,target_network_acl_name")
    self.assertEquals(target_network_acl_id, result)

  def test_ec2_network_network_acl_id_no_match(self):
    """
    Tests ec2_network_network_acl_id to see if it returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    network_acl_response = {
      "NetworkAcls": []
    }
    self._clients["ec2"].describe_network_acls.return_value = network_acl_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:network/network-acl-id,cant_possibly_match")
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

  def test_ec2_subnet_subnet_cidr(self):
    """
    Tests ec2_subnet_subnet_cidr to see if it returns a subnet CDIR based on matching subnet name in tag

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_subnet_cidr = "0.0.0.0/0"
    subnet_response = {
      "Subnets": [
        {
          "CidrBlock": target_subnet_cidr
        }
      ]
    }
    self._clients["ec2"].describe_subnets.return_value = subnet_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:subnet/subnet-cidr,target_subnet_name")
    self.assertEquals(target_subnet_cidr, result)

  def test_ec2_subnet_subnet_cidr_no_match(self):
    """
    Tests ec2_subnet_subnet_cidr to see if it returns None when there is no match

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
    result = ef_aws_resolver.lookup("ec2:subnet/subnet-cidr,cant_possibly_match")
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

  def test_ec2_transit_gateway_id(self):
    """
    Tests ec2_transit_gateway_id to see if it returns a transit gateway id based on matching transit gateway arn

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_transit_gateway_id = "tgw-0011"
    transit_gateway_response = {
      "TransitGateways": [
        {
          "TransitGatewayId": target_transit_gateway_id,
          "TransitGatewayArn": "target_transit_gateway_arn"
        }
      ]
    }
    self._clients["ec2"].describe_transit_gateways.return_value = transit_gateway_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:transit-gateway/transit-gateway-id,target_transit_gateway_arn")
    self.assertEquals(target_transit_gateway_id, result)

  def test_ec2_transit_gateway_id_no_match(self):
    """
    Tests ec2_transit_gateway_id to see if it returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    transit_gateway_response = {
      "TransitGateways": []
    }
    self._clients["ec2"].describe_transit_gateways.return_value = transit_gateway_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:transit-gateway/transit-gateway-id,cant_possibly_match")
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

  def test_ec2_vpc_endpoint_id(self):
    """
    Tests that this function returns the vpc endpoint id when it finds a
    resource with the right tag.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    expected_vpce_id = "vpce-123"
    describe_vpce_response = {
      "VpcEndpoints": [
        {
          "VpcEndpointId": "vpce-123",
          "VpcEndpointType": "Interface",
          "VpcId": "vpc-01"
        }
      ]
    }
    self._clients["ec2"].describe_vpc_endpoints.return_value = describe_vpce_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc-endpoint/vpc-endpoint-id,target_vpc_endpoint_name")
    self.assertEquals(expected_vpce_id, result)

  def test_ec2_vpc_endpoint_id_none(self):
    """
    Tests that this function returns None if it can't find a match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    describe_vpce_response = {
      "VpcEndpoints": []
    }
    self._clients["ec2"].describe_vpc_endpoints.return_value = describe_vpce_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc-endpoint/vpc-endpoint-id,target_vpc_endpoint_name")
    self.assertIsNone(result)

  def test_ec2_vpc_endpoint_id_by_vpc_service_one_vpce(self):
    """
    Tests that this function returns the VPC endpoint ID when it finds the VPC ID,
    and a single VPC endpoint matching the VPC ID + service.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    expected_vpce_id = "vpce-456"
    describe_vpc_response = {
      "Vpcs": [
        {
          "VpcId": "vpc-123"
        }
      ]
    }
    describe_vpce_response = {
      "VpcEndpoints": [
        {
          "VpcEndpointId": "vpce-456",
          "VpcEndpointType": "Interface",
          "VpcId": "vpc-123",
          "CreationTimestamp": datetime.datetime(2020,1,2),
          "ServiceName": "target_service_name"
        }
      ]
    }
    self._clients["ec2"].describe_vpcs.return_value = describe_vpc_response
    self._clients["ec2"].describe_vpc_endpoints.return_value = describe_vpce_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc-endpoint/vpc-endpoint-id/by-vpc-service,target_vpc_name/target_service_name")
    self.assertEquals(expected_vpce_id, result)

  def test_ec2_vpc_endpoint_id_by_vpc_service_3_vpces(self):
    """
    Tests that this function returns the ID of the oldest VPC endpoint when it finds multiple
    VPC endpoints in this VPC for this service.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    expected_vpce_id = "vpce-2" # Oldest creation timestamp
    describe_vpc_response = {
      "Vpcs": [
        {
          "VpcId": "vpc-123"
        }
      ]
    }
    describe_vpce_response = {
      "VpcEndpoints": [
        {
          "VpcEndpointId": "vpce-1",
          "VpcEndpointType": "Interface",
          "VpcId": "vpc-123",
          "CreationTimestamp": datetime.datetime(2020,1,2),
          "ServiceName": "target_service_name"
        },
        {
          "VpcEndpointId": "vpce-2",
          "VpcEndpointType": "Interface",
          "VpcId": "vpc-123",
          "CreationTimestamp": datetime.datetime(2019,12,2),
          "ServiceName": "target_service_name"
        },
        {
          "VpcEndpointId": "vpce-3",
          "VpcEndpointType": "Interface",
          "VpcId": "vpc-123",
          "CreationTimestamp": datetime.datetime(2020,3,2),
          "ServiceName": "target_service_name"
        }
      ]
    }
    self._clients["ec2"].describe_vpcs.return_value = describe_vpc_response
    self._clients["ec2"].describe_vpc_endpoints.return_value = describe_vpce_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc-endpoint/vpc-endpoint-id/by-vpc-service,target_vpc_name/target_service_name")
    self.assertEquals(expected_vpce_id, result)

  def test_ec2_vpc_endpoint_id_by_vpc_service_no_vpc_id(self):
    """
    Tests that this function returns the default value if no VPC ID could be found.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    describe_vpc_response = {
      "Vpcs": []
    }
    self._clients["ec2"].describe_vpcs.return_value = describe_vpc_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc-endpoint/vpc-endpoint-id/by-vpc-service,target_vpc_name/target_service_name,default-value")
    self.assertEquals("default-value", result)

  def test_ec2_vpc_endpoint_id_by_vpc_service_no_vpce(self):
    """
    Tests that this function returns the default value if no VPC endpoints are found.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    expected_vpce_id = "vpce-456"
    describe_vpc_response = {
      "Vpcs": [
        {
          "VpcId": "vpc-123"
        }
      ]
    }
    describe_vpce_response = {
      "VpcEndpoints": []
    }
    self._clients["ec2"].describe_vpcs.return_value = describe_vpc_response
    self._clients["ec2"].describe_vpc_endpoints.return_value = describe_vpce_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc-endpoint/vpc-endpoint-id/by-vpc-service,target_vpc_name/target_service_name,default-value")
    self.assertEquals("default-value", result)

  def test_ec2_vpc_endpoint_id_by_vpc_service_missing_args(self):
    """
    Tests that this function raises an Error if the vpc name or the service name are not provided.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    ef_aws_resolver = EFAwsResolver(self._clients)
    try:
      ef_aws_resolver.lookup("ec2:vpc-endpoint/vpc-endpoint-id/by-vpc-service,target_vpc_name,default-value")
      self.assertIsNone("Should have raised an error")
    except:
      self.assertTrue(True)

  def test_ec2_vpc_vpn_gateway_id(self):
    """
    Tests VPN Gateway ID lookup
    """
    vpn_gateway_id = "vgw-6cc41f72"
    vpn_gateway_response = {
      "VpnGateways": [
        {
          "VpnGatewayId": vpn_gateway_id
        }
      ]
    }
    self._clients["ec2"].describe_vpn_gateways.return_value = vpn_gateway_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ec2:vpc/vpn-gateway-id,vpnGateway-name")
    self.assertEquals(vpn_gateway_id, result)

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

  _HOSTED_ZONE_ID_PREFIX = "/hostedzone/"

  def _generate_hosted_zones_list(self, make_empty=False):
    """
    Generates a generic hosted zones JSON object. IsTruncated is False. Can be an empty list or one with dummy
    hosted zones.

    Args:
      make_empty: bool

    Returns:
      Dictionary object of hosted zones
    """
    if make_empty:
      hosted_zones = {
        "HostedZones": [],
        "IsTruncated": False
      }
    else:
      hosted_zones = {
        "HostedZones": [
          {
            "Config": {
                "PrivateZone": True
            },
            "Id": self._HOSTED_ZONE_ID_PREFIX + "AAAAA1",
            "Name": "other_domain.com."
          },
          {
            "Config": {
                "PrivateZone": False
            },
            "Id": self._HOSTED_ZONE_ID_PREFIX + "AAAAA2",
            "Name": "other_domain.com."
          },
          {
            "Config": {
                "PrivateZone": True
            },
            "Id": self._HOSTED_ZONE_ID_PREFIX + "BBBBB1",
            "Name": "another_domain.com"
          },
          {
            "Config": {
              "PrivateZone": False
            },
            "Id": self._HOSTED_ZONE_ID_PREFIX + "BBBBB2",
            "Name": "another_domain.com"
          }
        ],
        "IsTruncated": False
      }
    return hosted_zones

  def _generate_hosted_zone(self, hosted_zone_id, hosted_zone_domain_name, is_private=False):
    """
    Generates a hosted zone with given parameters

    Args:
      hosted_zone_id: string
      hosted_zone_domain_name: string
      is_private: bool

    Returns:
      Dictionary object of a hosted zone
    """
    hosted_zone = {
        "Config": {
            "PrivateZone": is_private
        },
        "Id": self._HOSTED_ZONE_ID_PREFIX + hosted_zone_id,
        "Name": hosted_zone_domain_name
    }
    return hosted_zone

  def _insert_hosted_zone_into_list(self, hosted_zone, hosted_zones_list):
    """
    Appends the hosted_zone to the hosted_zones_list

    Args:
      hosted_zone: Dictionary object of one hosted zone
      hosted_zones_list: Dictionary object of a hosted zones list

    Returns:
      None
    """
    if hosted_zones_list and hosted_zones_list.get("HostedZones", None) and hosted_zone:
      hosted_zones_list["HostedZones"].append(hosted_zone)

  def _set_hosted_zones_list_to_truncated(self, hosted_zones_list):
    """
    Sets the IsTruncated field to True and adds the NextHostedZoneId and NextDNSName field like an actual
    JSON response from Amazon would if the number of items in a result excited max items size.

    Args:
      hosted_zones_list: Dictionary object

    Returns:
      None
    """
    if hosted_zones_list:
      hosted_zones_list["IsTruncated"] = True
      hosted_zones_list["NextHostedZoneId"] = "ZZZZZ1"
      hosted_zones_list["NextDNSName"] = "whatever_domain.com"

  def test_route53_public_hosted_zone_id(self):
    """
    Tests route53_public_hosted_zone_id to see if it returns the hosted zone Id given the domain name and if the
    hosted zone is not private

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Sets the fields of the target hosted zone
    target_hosted_zone_id = "112233"
    target_hosted_zone_name = "target_domain.com."

    # Generates a list of hosted zones with the target hosted zone inside that list
    hosted_zones_list = self._generate_hosted_zones_list()
    target_hosted_zone = self._generate_hosted_zone(target_hosted_zone_id, target_hosted_zone_name)
    self._insert_hosted_zone_into_list(target_hosted_zone, hosted_zones_list)

    # Test the function and assert the results
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_list
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
    # Generate first truncated hosted zones list
    first_hosted_zones_list = self._generate_hosted_zones_list()
    self._set_hosted_zones_list_to_truncated(first_hosted_zones_list)

    # Set the fields of the target hosted zone
    target_hosted_zone_id = "112233"
    target_hosted_zone_name = "my_domain.com."

    # Generate second hosted zones list with target hosted zone in it
    second_hosted_zones_list = self._generate_hosted_zones_list()
    target_hosted_zone = self._generate_hosted_zone(target_hosted_zone_id, target_hosted_zone_name)
    self._insert_hosted_zone_into_list(target_hosted_zone, second_hosted_zones_list)

    # Test the function and assert the results
    self._clients["route53"].list_hosted_zones_by_name.side_effect = [first_hosted_zones_list, second_hosted_zones_list]
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
    # Generate hosted zones list, no target hosted zone in it
    hosted_zones_list = self._generate_hosted_zones_list()

    # Test the function and assert the results
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_list
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("route53:public-hosted-zone-id,cant_possibly_match.")
    self.assertIsNone(result)

    # Generated empty hosted zones list
    hosted_zones_list = self._generate_hosted_zones_list(make_empty=True)

    # Test the function and assert the results
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_list
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
    # Generate values for target hosted zone
    target_hosted_zone_id = "112233"
    target_hosted_zone_name = "my_domain.com."

    # Generate hosted zones list with target hosted zone in it
    hosted_zones_list = self._generate_hosted_zones_list()
    target_hosted_zone = self._generate_hosted_zone(target_hosted_zone_id, target_hosted_zone_name, is_private=True)
    self._insert_hosted_zone_into_list(target_hosted_zone, hosted_zones_list)

    # Test the function and assert the results
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_list
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
    # Create first hosted zones list and set it to truncated
    first_hosted_zones_list = self._generate_hosted_zones_list()
    self._set_hosted_zones_list_to_truncated(first_hosted_zones_list)

    # Generate values for target hosted zone
    target_hosted_zone_id = "112233"
    target_hosted_zone_name = "my_domain.com."

    # Generate second hosted zones list with target hosted zone in it
    second_hosted_zones_list = self._generate_hosted_zones_list()
    target_hosted_zone = self._generate_hosted_zone(target_hosted_zone_id, target_hosted_zone_name, is_private=True)
    self._insert_hosted_zone_into_list(target_hosted_zone, second_hosted_zones_list)

    # Test the function and assert the results
    self._clients["route53"].list_hosted_zones_by_name.side_effect = [first_hosted_zones_list,
                                                                      second_hosted_zones_list]
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
    # Generate hosted zones list without target hosted zone
    hosted_zones_list = self._generate_hosted_zones_list()

    # Test the function and assert the results
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_list
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("route53:private-hosted-zone-id,cant_possibly_match.")
    self.assertIsNone(result)

    # Generate empty hosted zones list
    hosted_zones_list = self._generate_hosted_zones_list(make_empty=True)

    # Test the function and assert the results
    self._clients["route53"].list_hosted_zones_by_name.return_value = hosted_zones_list
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
    """
    Tests cloudfront_domain_name to see if it returns the correct domain name given an alias

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_domain_name = "1122aabb.cloudfront.net"
    target_distribution_alias = "my_distribution"
    distribution_response = {
      "DistributionList": {
        "Items": [
          {
            "DomainName": target_domain_name,
            "Aliases": {
              "Items": [
                target_distribution_alias
              ],
              "Quantity": 1
            }
          }
        ],
        "Quantity": 1,
        "IsTruncated": False
      }
    }
    self._clients["cloudfront"].list_distributions.return_value = distribution_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cloudfront:domain-name," + target_distribution_alias)
    self.assertEquals(target_domain_name, result)

  def test_cloudfront_domain_name_is_truncated(self):
    """
    Tests cloudfront_domain_name to see if it returns the correct domain name when the results have to be truncated

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_domain_name = "1122aabb.cloudfront.net"
    target_distribution_alias = "my_distribution"
    first_distribution_response = {
      "DistributionList": {
        "Items": [
          {
            "DomainName": "otherdomain.cloudfront.net",
            "Aliases": {
              "Items": [
                "other_cloud_front"
              ],
              "Quantity": 1
            }
          }
        ],
        "Quantity": 1,
        "IsTruncated": True,
        "NextMarker": "111aaabbb222=="
      }
    }
    second_distribution_response = {
      "DistributionList": {
        "Items": [
          {
            "DomainName": target_domain_name,
            "Aliases": {
              "Items": [
                target_distribution_alias
              ],
              "Quantity": 1
            }
          }
        ],
        "Quantity": 1,
        "IsTruncated": False
      }
    }
    self._clients["cloudfront"].list_distributions.side_effect = [first_distribution_response,
                                                                  second_distribution_response]
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cloudfront:domain-name," + target_distribution_alias)
    self.assertEquals(target_domain_name, result)

  def test_cloudfront_domain_name_no_match(self):
    """
    Tests cloudfront_domain_name to see if it returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    distribution_response = {
      "DistributionList": {
        "Items": [
          {
            "DomainName": "something.cloudfront.net",
            "Aliases": {
              "Items": [
                "my_alias"
              ],
              "Quantity": 1
            }
          }
        ],
        "Quantity": 1,
        "IsTruncated": False
      }
    }
    self._clients["cloudfront"].list_distributions.return_value = distribution_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cloudfront:domain-name,cant_possibly_match")
    self.assertIsNone(result)

    distribution_response = {
      "DistributionList": {
        "Items": [],
        "Quantity": 0,
        "IsTruncated": False
      }
    }
    self._clients["cloudfront"].list_distributions.return_value = distribution_response
    result = ef_aws_resolver.lookup("cloudfront:domain-name,cant_possibly_match")
    self.assertIsNone(result)

  def _generate_cloudfront_origin_access_identity_list(self, make_empty=False):
    """
    Generate generic cloudfront origin access identity list. Can make a empty or non empty list.

    Args:
      make_empty: bool

    Returns:
      Dictionary object of cloud front origin access identity list

    """
    if make_empty:
      cloudfront_origin_access_identity_list = {
        "CloudFrontOriginAccessIdentityList": {
          "Items": [],
          "IsTruncated": False
        }
      }
    else:
      cloudfront_origin_access_identity_list = {
        "CloudFrontOriginAccessIdentityList": {
          "Items": [
            {
              "Comment": "one comment",
              "S3CanonicalUserId": "1a2b3c",
              "Id": "AAAAAA1"
            },
            {
              "Comment": "another comment",
              "S3CanonicalUserId": "1aa2bb3cc",
              "Id": "AAAAAA2"
            },
            {
              "Comment": "other comment",
              "S3CanonicalUserId": "1aaa2bbb3ccc",
              "Id": "AAAAAA3"
            }
          ],
          "IsTruncated": False
        }
      }
    return cloudfront_origin_access_identity_list

  def _generate_cloudfront_origin_access_identity(self, comment, id=None, s3_canonical_user_id=None):
    """
    Generates a cloudfront origin access identity

    Args:
      comment: string
      id: string
      s3_canonical_user_id: string, default None

    Returns:
      Dictdionary object of a cloudfront origin access identity
    """
    cloudfront_origin_access_identity = {
      "Comment": comment,
      "S3CanonicalUserId": s3_canonical_user_id,
      "Id": id
    }
    return cloudfront_origin_access_identity

  def _insert_cloudfront_origin_access_identity_into_list(self, cloudfront_origin_access_identity,
                                                          cloudfront_origin_access_identity_list):
    """
    Insert cloudfront origin access identity into cloudfront origin access identity list

    Args:
      cloudfront_origin_access_identity: dictionary object of cloudfront origin access identity
      cloudfront_origin_access_identity_list: dictionary object of cloudfront origin access identity list

    Returns:
      None
    """
    if cloudfront_origin_access_identity_list and \
      cloudfront_origin_access_identity_list.get("CloudFrontOriginAccessIdentityList", None) and \
      cloudfront_origin_access_identity_list["CloudFrontOriginAccessIdentityList"].get("Items", None):
      cloudfront_origin_access_identity_list["CloudFrontOriginAccessIdentityList"]["Items"].append(
        cloudfront_origin_access_identity)

  def _set_cloudfront_origin_access_identity_list_to_truncated(self, cloudfront_origin_access_identity_list):
    """
    Modify the cloudfront origin access identity list to truncated and add a NextMarker field

    Args:
      cloudfront_origin_access_identity_list: Dictionary object of cloudfront origin access identity list

    Returns:
      None
    """
    if cloudfront_origin_access_identity_list and \
        cloudfront_origin_access_identity_list.get("CloudFrontOriginAccessIdentityList", None):
      cloudfront_origin_access_identity_list["CloudFrontOriginAccessIdentityList"]["IsTruncated"] = True
      cloudfront_origin_access_identity_list["CloudFrontOriginAccessIdentityList"]["NextMarker"] = "aabbcc"


  def test_cloudfront_origin_access_identity_oai_id(self):
    """
    Tests cloudfront_origin_access_identity_oai_id to see if it returns the correct origin access identity id based
    on comment given

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Generate values for target identity
    target_comment = "target comment"
    target_id = "TARGET_ID"

    # Generate cloudfront origin access identity list with target in it
    cloudfront_origin_access_identity_list = self._generate_cloudfront_origin_access_identity_list()
    cloudfront_origin_access_identity = self._generate_cloudfront_origin_access_identity(target_comment, id=target_id)
    self._insert_cloudfront_origin_access_identity_into_list(cloudfront_origin_access_identity,
                                                             cloudfront_origin_access_identity_list)

    # Test method and assert results
    self._clients["cloudfront"].list_cloud_front_origin_access_identities.return_value = \
      cloudfront_origin_access_identity_list
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cloudfront:origin-access-identity/oai-id," + target_comment)
    self.assertEquals(target_id, result)

  def test_cloudfront_origin_access_identity_oai_id_is_truncated(self):
    """
    Tests cloudfront_origin_access_identity_oai_id to see if it returns the correct id when the results are truncated

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Generate values for target identity
    target_comment = "target comment"
    target_id = "TARGET_ID"

    # Generate first cloudfront origin access identity list and truncate it
    first_cloudfront_origin_access_identity_list = self._generate_cloudfront_origin_access_identity_list()
    self._set_cloudfront_origin_access_identity_list_to_truncated(first_cloudfront_origin_access_identity_list)

    # Generate second cloudfront origin access identity list with target in it
    second_cloudfront_origin_access_identity_list = self._generate_cloudfront_origin_access_identity_list()
    cloudfront_origin_access_identity = self._generate_cloudfront_origin_access_identity(target_comment, id=target_id)
    self._insert_cloudfront_origin_access_identity_into_list(cloudfront_origin_access_identity,
                                                             second_cloudfront_origin_access_identity_list)

    # Test method and assert results
    self._clients["cloudfront"].list_cloud_front_origin_access_identities.side_effect = \
      [first_cloudfront_origin_access_identity_list, second_cloudfront_origin_access_identity_list]
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cloudfront:origin-access-identity/oai-id," + target_comment)
    self.assertEquals(target_id, result)

  def test_cloudfront_origin_access_identity_oai_id_no_match(self):
    """
    Tests cloudfront_origin_access_identity_oai_id to see if it returns None when there are no matches

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Generate list without target in it
    cloudfront_origin_access_identity_list = self._generate_cloudfront_origin_access_identity_list()

    self._clients["cloudfront"].list_cloud_front_origin_access_identities.return_value = \
      cloudfront_origin_access_identity_list
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cloudfront:origin-access-identity/oai-id,cant_possibly_match")
    self.assertIsNone(result)

    # Generate empty list
    cloudfront_origin_access_identity_list = self._generate_cloudfront_origin_access_identity_list(make_empty=True)

    self._clients["cloudfront"].list_cloud_front_origin_access_identities.return_value = \
      cloudfront_origin_access_identity_list
    result = ef_aws_resolver.lookup("cloudfront:origin-access-identity/oai-id,cant_possibly_match")
    self.assertIsNone(result)

  def test_cloudfront_origin_access_identity_oai_canonical_user_id(self):
    """
    Tests cloudfront_origin_access_identity_oai_canonical_user_id to see if it returns the correct id based on given
    comment

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Generate values for target
    target_comment = "target comment"
    target_s3_canonical_user_id = "target_canonical_id"

    # Generate list with target in it
    cloudfront_origin_access_identity_list = self._generate_cloudfront_origin_access_identity_list()
    cloudfront_origin_access_identity = self._generate_cloudfront_origin_access_identity(
      target_comment, s3_canonical_user_id=target_s3_canonical_user_id)
    self._insert_cloudfront_origin_access_identity_into_list(cloudfront_origin_access_identity,
                                                             cloudfront_origin_access_identity_list)

    # Test method and assert results
    self._clients["cloudfront"].list_cloud_front_origin_access_identities.return_value = \
      cloudfront_origin_access_identity_list
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cloudfront:origin-access-identity/oai-canonical-user-id," + target_comment)
    self.assertEquals(target_s3_canonical_user_id, result)

  def test_cloudfront_origin_access_identity_oai_canonical_user_id_is_truncated(self):
    """
    Tests cloudfront_origin_access_identity_oai_canonical_user_id to see if it returns the correct id when the result
    is truncated

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Generate target values
    target_comment = "target comment"
    target_s3_canonical_user_id = "target_canonical_id"

    # Generate first list and set it to truncated
    first_cloudfront_origin_access_identity_list = self._generate_cloudfront_origin_access_identity_list()
    self._set_cloudfront_origin_access_identity_list_to_truncated(first_cloudfront_origin_access_identity_list)

    # Generate second list and insert target into it
    second_cloudfront_origin_access_identity_list = self._generate_cloudfront_origin_access_identity_list()
    cloudfront_origin_access_identity = self._generate_cloudfront_origin_access_identity(
      target_comment, s3_canonical_user_id=target_s3_canonical_user_id)
    self._insert_cloudfront_origin_access_identity_into_list(cloudfront_origin_access_identity,
                                                             second_cloudfront_origin_access_identity_list)

    # Test method and assert results
    self._clients["cloudfront"].list_cloud_front_origin_access_identities.side_effect = \
      [first_cloudfront_origin_access_identity_list, second_cloudfront_origin_access_identity_list]
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cloudfront:origin-access-identity/oai-canonical-user-id," + target_comment)
    self.assertEquals(target_s3_canonical_user_id, result)

  def test_cloudfront_origin_access_identity_oai_canonical_user_id_no_match(self):
    """
    Tests cloudfront_origin_access_identity_oai_canonical_user_id to see if it returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Generate list with no target in it
    cloudfront_origin_access_identity_list = self._generate_cloudfront_origin_access_identity_list()

    # Test method and assert results
    self._clients["cloudfront"].list_cloud_front_origin_access_identities.return_value = \
      cloudfront_origin_access_identity_list
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cloudfront:origin-access-identity/oai-canonical-user-id,cant_possibly_match")
    self.assertIsNone(result)

    # Generate empty list
    cloudfront_origin_access_identity_list = self._generate_cloudfront_origin_access_identity_list(make_empty=True)

    # Test method and assert results
    self._clients["cloudfront"].list_cloud_front_origin_access_identities.return_value = \
      cloudfront_origin_access_identity_list
    result = ef_aws_resolver.lookup("cloudfront:origin-access-identity/oai-canonical-user-id,cant_possibly_match")
    self.assertIsNone(result)

  def _generate_cognito_identity_identity_pool_list(self):
    identity_pool_list = \
      {
        "IdentityPools": [
          {
            "IdentityPoolId": "us-west-2:staging_pool_id",
            "IdentityPoolName": "staging_cms_identity_pool"
          },
          {
            "IdentityPoolId": "us-west-2:proto0_pool_id",
            "IdentityPoolName": "proto0_cms_identity_pool"
          }
        ]
      }
    return identity_pool_list

  def test_cognito_identity_identity_pool_arn(self):
    # Mock the return values involved with this lookup
    self._clients["cognito-identity"].list_identity_pools.return_value = \
      self._generate_cognito_identity_identity_pool_list()

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cognito-identity:identity-pool-arn,proto0_cms_identity_pool")
    self.assertEqual("arn:aws:cognito-identity:{{REGION}}:{{ACCOUNT}}:identitypool/us-west-2:proto0_pool_id",
                     result)

  def test_cognito_identity_identity_pool_arn_no_match(self):
    # Mock the return values involved with this lookup
    self._clients["cognito-identity"].list_identity_pools.return_value = \
      self._generate_cognito_identity_identity_pool_list()

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cognito-identity:identity-pool-arn,no_match")
    self.assertIsNone(result)

  def test_cognito_identity_identity_pool_id(self):
    # Mock the return values involved with this lookup
    self._clients["cognito-identity"].list_identity_pools.return_value = \
      self._generate_cognito_identity_identity_pool_list()

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cognito-identity:identity-pool-id,proto0_cms_identity_pool")
    self.assertEqual("us-west-2:proto0_pool_id", result)

  def test_cognito_identity_identity_pool_id_no_match(self):
    # Mock the return values involved with this lookup
    self._clients["cognito-identity"].list_identity_pools.return_value = \
      self._generate_cognito_identity_identity_pool_list()

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cognito-identity:identity-pool-id,no_match")
    self.assertIsNone(result)

  def _generate_cognito_idp_user_pool_list(self):
    user_pool_list = \
      {
        "UserPools": [
          {
            "Id": "us-west-2_staging-user-pool-id",
            "Name": "staging-cms-user-pool"
          },
          {
            "Id": "us-west-2_proto0-user-pool-id",
            "Name": "proto0-cms-user-pool"
          }
        ]
      }
    return user_pool_list

  def _generate_cognito_idp_user_pool(self):
    user_pool = \
      {
        "UserPool": {
          "Id": "proto0-cms-user-pool",
          "Arn": "arn:aws:cognito-idp:us-west-2:123:userpool/us-west-2_proto0-user-pool-id"
        }
      }
    return user_pool

  def test_cognito_idp_user_pool_arn(self):
    # Mock the return values involved with this lookup
    self._clients["cognito-idp"].list_user_pools.return_value = self._generate_cognito_idp_user_pool_list()
    self._clients["cognito-idp"].describe_user_pool.return_value = self._generate_cognito_idp_user_pool()

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cognito-idp:user-pool-arn,proto0-cms-user-pool")
    self.assertEqual("arn:aws:cognito-idp:us-west-2:123:userpool/us-west-2_proto0-user-pool-id", result)

  def test_cognito_idp_user_pool_arn_no_match(self):
    # Mock the return values involved with this lookup
    self._clients["cognito-idp"].list_user_pools.return_value = self._generate_cognito_idp_user_pool_list()
    self._clients["cognito-idp"].describe_user_pool.return_value = self._generate_cognito_idp_user_pool()

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cognito-idp:user-pool-arn,no_match")
    self.assertIsNone(result)

  def test_cognito_idp_user_pool_id(self):
    # Mock the return values involved with this lookup
    self._clients["cognito-idp"].list_user_pools.return_value = self._generate_cognito_idp_user_pool_list()

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cognito-idp:user-pool-id,proto0-cms-user-pool")
    self.assertEqual("us-west-2_proto0-user-pool-id", result)

  def test_cognito_idp_user_pool_id_no_match(self):
    # Mock the return values involved with this lookup
    self._clients["cognito-idp"].list_user_pools.return_value = self._generate_cognito_idp_user_pool_list()

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("cognito-idp:user-pool-id,no_match")
    self.assertIsNone(result)

  def test_lookup_invalid_input(self):
    """
    Tests lookup with all invalid inputs

    NOTE: Don't need to create valid input test cases since all the other unit tests do that with each different
    lookup.

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    ef_aws_resolver = EFAwsResolver(self._clients)

    result = ef_aws_resolver.lookup(None)
    self.assertIsNone(result)

    result = ef_aws_resolver.lookup("service_does_not_exist")
    self.assertIsNone(result)

    result = ef_aws_resolver.lookup("")
    self.assertIsNone(result)

  def test_kms_decrypt_value(self):
    """
    Test kms value decryption

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    decrypted_value = "KMS DECRYPTED THIS"
    encrypted_value = base64.b64encode(decrypted_value)
    # Set mock value for describe_key
    decrypt =self._clients["kms"].decrypt
    decrypt.return_value = {
      "Plaintext": decrypted_value,
      "KeyId": "KEY_ID"
    }

    ef_aws_resolver = EFAwsResolver(self._clients)

    result = ef_aws_resolver.lookup("kms:decrypt,{}=".format(encrypted_value))

    decrypt.assert_called_with(CiphertextBlob='KMS DECRYPTED THIS')
    self.assertEquals(result, decrypted_value)

  def test_kms_key_arn(self):
    """
    Test lookup key arn, valid scenario with success

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    # Set mock value for describe_key
    self._clients["kms"].describe_key.return_value = \
      {
        "KeyMetadata": {
          "Origin": "AWS_KMS",
          "KeyId": "88888888-8888",
          "Description": "The master key",
          "KeyManager": "CUSTOMER",
          "Enabled": True,
          "KeyUsage": "ENCRYPT_DECRYPT",
          "KeyState": "Enabled",
          "CreationDate": 1524599639.111,
          "Arn": "arn:aws:kms:us-west-2:8888:key/88888888-8888",
          "AWSAccountId": "4444"
        }
      }

    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("kms:key_arn,alias/proto0-master-key")
    self.assertEquals(result, "arn:aws:kms:us-west-2:8888:key/88888888-8888")

  def test_kms_key_arn_key_does_not_exist(self):
    """
    Tests for when key doesn't exist, and that the function raises an exception

    Raises:
      AssertionError if any of the assert checks fail
    """
    self._clients["kms"].describe_key.side_effect = ClientError(
      {
        'Error':
          {
            'Code': 000,
            'Message': "Key doesn't exist.",
            'Type': "KMS"
          }
      },
      'describe_key'
    )
    ef_aws_resolver = EFAwsResolver(self._clients)
    with self.assertRaises(RuntimeError):
      ef_aws_resolver.lookup("kms:key_arn,alias/key_no_exist")

  def test_ecr_repository_image_name(self):
    """
    Tests for ECR Image name lookup
    """
    image_name = "service-ecr"
    repository_uri = 'account-id.dkr.ecr.us-west-2.amazonaws.com/{}'.format(image_name)
    self._clients["ecr"].describe_repositories.return_value = \
      {
        'repositories': [{
          'repositoryArn': 'arn:aws:ecr:region:account-id:respository/{}'.format(image_name),
          'repositoryName': image_name,
          'repositoryUri': repository_uri,
        }]
      }
    ef_aws_resolver = EFAwsResolver(self._clients)
    self.assertEqual(
      ef_aws_resolver.lookup("ecr:repository/image-name,%s" % image_name),
      repository_uri
    )

  def test_ecr_repository_image_name_no_such_repository(self):
    """
    Tests for ECR Image name lookup
    """
    image_name = "service-ecr"
    repository_uri = 'account-id.dkr.ecr.us-west-2.amazonaws.com/{}'.format(image_name)
    self._clients["ecr"].describe_repositories.return_value = \
      {
        'repositories': []
      }
    ef_aws_resolver = EFAwsResolver(self._clients)
    self.assertIsNone(ef_aws_resolver.lookup("ecr:repository/image-name,%s" % image_name))

  def test_elbv2_load_balancer_hosted_zone(self):
    """
    Tests for ELBv2 hosted zone lookup
    """
    hosted_zone = "ELBV2_hosted_zone"
    lb_name = "env-balancer-name"
    lb_description = {
        u'LoadBalancers': [{
            u'CanonicalHostedZoneId': hosted_zone,
            u'DNSName': 'load-balancer.ellation.com',
            u'LoadBalancerName': lb_name,
            }],
        }
    self._clients["elbv2"].describe_load_balancers.return_value = lb_description
    ef_aws_resolver = EFAwsResolver(self._clients)
    self.assertEqual(
      ef_aws_resolver.lookup("elbv2:load-balancer/hosted-zone,%s" % lb_name),
      hosted_zone)

  def test_elbv2_load_balancer_no_such_elb(self):
    """
    Tests for fail in case of a missing ELBv2 attribute lookup
    """
    lb_name = "env-balancer-name"
    error = ClientError(
            error_response={
                'Error': {'Code': 'LoadBalancerNotFound',
                    'Message': "Load balancers '[%s]' not found" % lb_name,
                    'Type': 'Sender'},
                'HTTPStatusCode': 400,
                'RequestId': 'ed43d22b-ddf9-11e8-a877-6f5e88f35437',
                'RetryAttempts': 0},
                operation_name="DescribeLoadBalancers")

    self._clients["elbv2"].describe_load_balancers.side_effect = error

    ef_aws_resolver = EFAwsResolver(self._clients)

    lookup_input = "elbv2:load-balancer/hosted-zone,{}".format(lb_name)
    self.assertEqual(
      ef_aws_resolver.lookup(lookup_input),
      None)

    lookup_input = "elbv2:load-balancer/dns-name,{}".format(lb_name)
    self.assertEqual(
      ef_aws_resolver.lookup(lookup_input),
      None)

    default = "default_value"
    lookup_input = "elbv2:load-balancer/hosted-zone,{},{}".format(lb_name, default)
    self.assertEqual(
      ef_aws_resolver.lookup(lookup_input),
      default)

    lookup_input = "elbv2:load-balancer/dns-name,{},{}".format(lb_name, default)
    self.assertEqual(
      ef_aws_resolver.lookup(lookup_input),
      default)

  def test_elbv2_load_balancer_dns_name(self):
    """
    Tests for ELBV2 DNS name lookup
    """
    hosted_zone = "ELBV2_hosted_zone"
    dns_name = 'load-balancer.ellation.com'
    lb_name = "env-balancer-name"
    lb_description = {
        u'LoadBalancers': [{
            u'CanonicalHostedZoneId': hosted_zone,
            u'DNSName': dns_name,
            u'LoadBalancerName': lb_name,
            }],
        }
    self._clients["elbv2"].describe_load_balancers.return_value = lb_description
    ef_aws_resolver = EFAwsResolver(self._clients)
    self.assertEqual(
      ef_aws_resolver.lookup("elbv2:load-balancer/dns-name,%s" % lb_name),
      dns_name)

  def test_elbv2_load_balancer_arn_suffix(self):
    """
    Tests for ELBV2 ARN suffix lookup
    """
    lb_name = "env-balancer-name"
    lb_arn_suffix = "app/env-balancer-name/0987654321"
    lb_arn = "arn:aws:elasticloadbalancing:us-west-2:123456789:loadbalancer/app/env-balancer-name/0987654321"
    self._clients["elbv2"].describe_load_balancers.return_value = {
        u'LoadBalancers': [{
            u'LoadBalancerArn': lb_arn,
            }],
        }
    ef_aws_resolver = EFAwsResolver(self._clients)
    self.assertEqual(
      ef_aws_resolver.lookup("elbv2:load-balancer/arn-suffix,%s" % lb_name),
      lb_arn_suffix)

  def test_elbv2_target_group_arn_suffix(self):
    """
    Tests for ELBV2 target group ARN suffix lookup
    """
    tg_name = "target-group-name"
    tg_arn_suffix = "targetgroup/target-group-name/0987654321"
    tg_arn = "arn:aws:elasticloadbalancing:us-west-2:123456789:targetgroup/target-group-name/0987654321"
    self._clients["elbv2"].describe_target_groups.return_value = {
        u'TargetGroups': [{
            u'TargetGroupArn': tg_arn,
            }],
        }
    ef_aws_resolver = EFAwsResolver(self._clients)
    self.assertEqual(
      ef_aws_resolver.lookup("elbv2:target-group/arn-suffix,%s" % tg_name),
      tg_arn_suffix)

  def test_ram_resource_share_arn(self):
    """
    Tests ram_resource_share_arn to see if it returns a resource share arn based on matching resource share name

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_resource_share_arn = "ram-0011"
    resource_share_response = {
      "resourceShares": [
        {
          "resourceShareArn": target_resource_share_arn,
          "name": "target_resource_share_name"
        }
      ]
    }
    self._clients["ram"].get_resource_shares.return_value = resource_share_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ram:resource-share/resource-share-arn,target_resource_share_name")
    self.assertEquals(target_resource_share_arn, result)

  def test_ram_resource_share_arn_no_match(self):
    """
    Tests ram_resource_share_arn to see if it returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    resource_share_response = {
      "resourceShares": []
    }
    self._clients["ram"].get_resource_shares.return_value = resource_share_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ram:resource-share/resource-share-arn,cant_possibly_match")
    self.assertIsNone(result)

  def test_ram_resource_arn(self):
    """
    Tests ram_resource_arn to see if it returns a resource arn based on matching resource share arn

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    target_resource_arn = "foo-0011"
    resource_response = {
      "resources": [
        {
          "arn": target_resource_arn,
          "resourceShareArn": "target_resource_share_arn"
        }
      ]
    }
    self._clients["ram"].list_resources.return_value = resource_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ram:resource-share/resource-arn,target_resource_share_arn")
    self.assertEquals(target_resource_arn, result)

  def test_ram_resource_arn_no_match(self):
    """
    Tests ram_resource_arn to see if it returns None when there is no match

    Returns:
      None

    Raises:
      AssertionError if any of the assert checks fail
    """
    resource_response = {
      "resources": []
    }
    self._clients["ram"].list_resources.return_value = resource_response
    ef_aws_resolver = EFAwsResolver(self._clients)
    result = ef_aws_resolver.lookup("ram:resource-share/resource-arn,cant_possibly_match")
    self.assertIsNone(result)
