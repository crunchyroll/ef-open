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

import boto3

from ef_aws_resolver import EFAwsResolver
from ef_config import EFConfig
from ef_context import EFContext
from ef_utils import fail, http_get_metadata, whereami

context = EFContext()
context.env = "mgmt.ellationeng"

class TestEFAwsResolver(unittest.TestCase):
  """Tests for `ef_aws_resolver.py`."""

  # initialize based on where running
  where = whereami()
  if where == "local":
    session = boto3.Session(profile_name=context.account_alias, region_name=EFConfig.DEFAULT_REGION)
  elif where == "ec2":
    region = http_get_metadata("placement/availability-zone/")
    region = region[:-1]
    session = boto3.Session(region_name=region)
  else:
    fail("Can't test in environment: " + where)

  clients = {
    "cloudformation": session.client("cloudformation"),
    "cloudfront": session.client("cloudfront"),
    "ec2": session.client("ec2"),
    "iam": session.client("iam"),
    "route53": session.client("route53"),
    "waf": session.client("waf")
  }


## Test coverage of ec2:eni/eni-id is disabled because the we are not presently creating
## ENI fixtures and this test does not at present generate an ENI for testing this lookup function
## Why are these retained here? The lookup function is still valid, and useful. We just can't test it at the moment
#  def test_ec2_eni_eni_id(self):
#    """Does ec2:eni/eni-id,eni-proto3-dnsproxy-1a resolve to an ENI ID"""
#    test_string = "ec2:eni/eni-id,eni-proto3-dnsproxy-1a"
#    resolver = EFAwsResolver(TestEFAwsResolver.clients)
#    self.assertRegexpMatches(resolver.lookup(test_string), "^eni-[a-f0-9]{8}$")

#  def test_ec2_eni_eni_id_none(self):
#    """Does ec2:eni/eni-id,cant_possibly_match return None"""
#    test_string = "ec2:eni/eni-id,cant_possibly_match"
#    resolver = EFAwsResolver(TestEFAwsResolver.clients)
#    self.assertIsNone(resolver.lookup(test_string))

#  def test_ec2_eni_eni_id_default(self):
#    """Does ec2:eni/eni-id,cant_possibly_match,DEFAULT return default value"""
#    test_string = "ec2:eni/eni-id,cant_possibly_match,DEFAULT"
#    resolver = EFAwsResolver(TestEFAwsResolver.clients)
#    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_ec2_elasticip_elasticip_id(self):
    """Does ec2:elasticip/elasticip-id,ElasticIpMgmtCingest1 resolve to elastic IP allocation ID"""
    test_string = "ec2:elasticip/elasticip-id,ElasticIpMgmtCingest1"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^eipalloc-[a-f0-9]{8}$")

  def test_ec2_elasticip_elasticip_id_none(self):
    """Does ec2:elasticip/elasticip-id,cant_possibly_match return None"""
    test_string = "ec2:elasticip/elasticip-id,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_ec2_elasticip_elasticip_id_default(self):
    """Does ec2:elasticip/elasticip-id,cant_possibly_match,DEFAULT return default value"""
    test_string = "ec2:elasticip/elasticip-id,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

  def test_ec2_elasticip_elasticip_ipaddress(self):
    """Does ec2:elasticip/elasticip-ipaddress,ElasticIpMgmtCingest1 resolve to elastic IP address"""
    test_string = "ec2:elasticip/elasticip-ipaddress,ElasticIpMgmtCingest1"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")

  def test_ec2_elasticip_elasticip_ipaddress_none(self):
    """Does ec2:elasticip/elasticip-ipaddress,cant_possibly_match return None"""
    test_string = "ec2:elasticip/elasticip-ipaddress,cant_possibly_match"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertIsNone(resolver.lookup(test_string))

  def test_ec2_elasticip_elasticip_ipaddress_default(self):
    """Does ec2:elasticip/elasticip-ipaddress,cant_possibly_match,DEFAULT return default value"""
    test_string = "ec2:elasticip/elasticip-ipaddress,cant_possibly_match,DEFAULT"
    resolver = EFAwsResolver(TestEFAwsResolver.clients)
    self.assertRegexpMatches(resolver.lookup(test_string), "^DEFAULT$")

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
