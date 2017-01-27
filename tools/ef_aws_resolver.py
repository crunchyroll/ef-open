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

from __future__ import print_function

import re

from botocore.exceptions import ClientError

class EFAwsResolver(object):
  """
  For keys to look up, we use partial ARN syntax to identify system and information sought:
  http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-ec2
  Not all possible lookups are supported

  Expects these clients to be pre-made and passed in:
    cloudfront, cloudformation, ec2, iam, lambda, route53, waf

  Example:
    the ARN of a security group ID is:
      arn:aws:ec2:us-west-2:1234567890:security-group/security-group-id
    following this pattern:
      arn:aws:<service>:<region>:<account-id>:<key>
    we trim it to:
      <service>:<key>
      ec2:security-group/security-group-id
    which becomes a template token with 'aws:' prepended to identify the lookup provider,
    and the search string appended:
      {{aws:ec2:security-group/security-group-id,proto2-ess-elb}}
    which then is passed to the lookup function here as:
      EFAwsResolver.lookup("ec2:security-group/security-group-id","proto2-ess-elb")
  """

  # dictionary of boto3 clients: {"ec2":ec2_client, ... } made with ef_utils.create_aws_clients
  __CLIENTS = {}

  def acm_certificate_arn(self, lookup, default=None):
    """
    Args:
      lookup: region,domain on the certificate to be looked up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      ARN of the certificate if found, or default/None if no match
    """
    try:
      # This a region-specific client, so we'll make a new client in the right place using existing SESSION
      region_name, domain_name = lookup.split("/")
      acm_client = EFAwsResolver.__CLIENTS["SESSION"].client(service_name="acm", region_name=region_name)
      response = acm_client.list_certificates(
        CertificateStatuses=['ISSUED'],
        MaxItems=100
      )
    except Exception:
      return default
    if len(response["CertificateSummaryList"]) < 1:
      return default
    for cert in response["CertificateSummaryList"]:
      if cert["DomainName"] == domain_name:
        return cert["CertificateArn"]
    return default

  def ec2_elasticip_elasticip_id(self, lookup, default=None):
    """
    Args:
      lookup: the CloudFormation resource name of the Elastic IP ID to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The ID of the first Elastic IP found with a description matching 'lookup' or default/None if no match found
    """
    public_ip = self.ec2_elasticip_elasticip_ipaddress(lookup)
    if public_ip is None:
      return default
    try:
      eips = EFAwsResolver.__CLIENTS["ec2"].describe_addresses(
        PublicIps=[public_ip]
      )
    # Public IP not found
    except ClientError:
      return default
    eip_id = eips["Addresses"][0]["AllocationId"]
    return eip_id

  def ec2_elasticip_elasticip_ipaddress(self, lookup, default=None):
    """
    Args:
      lookup: the CloudFormation resource name of the Elastic IP address to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The IP address of the first Elastic IP found with a description matching 'lookup' or default/None if no match
    """
    # Extract environment from resource ID to build stack name
    m = re.search('(ElasticIp)([A-Z][a-z]+)([A-Z][a-z]+)([0-9])', lookup)
    # The lookup string was not a valid ElasticIp resource label
    if m is None:
      return default
    env = m.group(2).lower()
    stackname = "{}-elasticip".format(env)
    # Look up the EIP resource in the stack to get the IP address assigned to the EIP
    eip_stack = EFAwsResolver.__CLIENTS["cloudformation"].describe_stack_resources(
      StackName=stackname,
      LogicalResourceId=lookup
    )
    # stack does not exist
    if len(eip_stack) < 1:
      return default
    stack_resources = eip_stack["StackResources"]
    # Resource does not exist in stack
    if len(stack_resources) < 1:
      return default
    eip_publicip = stack_resources[0]["PhysicalResourceId"]
    return eip_publicip

  def ec2_eni_eni_id(self, lookup, default=None):
    """
    Args:
      lookup: the description of the Elastic Network Interface (ENI) to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The ID of the first ENI found with a description matching 'lookup' or default/None if no match found
    """
    enis = EFAwsResolver.__CLIENTS["ec2"].describe_network_interfaces(Filters=[{
      'Name': 'description',
      'Values': [lookup]
    }])
    if len(enis.get("NetworkInterfaces")) > 0:
      return enis["NetworkInterfaces"][0]["NetworkInterfaceId"]
    else:
      return default

  def ec2_security_group_security_group_id(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of a security group to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      Security group ID if target found or default/None if no match
    """
    try:
      response = EFAwsResolver.__CLIENTS["ec2"].describe_security_groups(Filters=[{
        'Name':'group-name', 'Values':[lookup]
      }])
    except:
      return default
    if len(response["SecurityGroups"]) > 0:
      return response["SecurityGroups"][0]["GroupId"]
    else:
      return default

  def ec2_subnet_subnet_id(self, lookup, default=None):
    """
    Return:
      the ID of a single subnet or default/None if no match
    Args:
      lookup: the friendly name of the subnet to look up (subnet-<env>-a or subnet-<env>-b)
      default: the optional value to return if lookup failed; returns None if not set
    """
    subnets = EFAwsResolver.__CLIENTS["ec2"].describe_subnets(Filters=[{
      'Name': 'tag:Name',
      'Values': [lookup]
    }])
    if len(subnets["Subnets"]) > 0:
      return subnets["Subnets"][0]["SubnetId"]
    else:
      return default

  def ec2_vpc_availabilityzones(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of a VPC to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      A comma-separated list of availability zones in use in the named VPC or default/None if no match
    """
    vpc_id = self.ec2_vpc_vpc_id(lookup)
    if vpc_id is None:
      return default
    subnets = EFAwsResolver.__CLIENTS["ec2"].describe_subnets(Filters=[{
      'Name': 'vpc-id',
      'Values': [vpc_id]
    }])
    if len(subnets["Subnets"]) > 0:
      # Strip the metadata section (subnets["Subnets"])
      az_list = [s["AvailabilityZone"] for s in subnets["Subnets"]]
      # Add internal ", " only. This is called literally from: "{{aws...}}" - CF template needs the outer quotes
      return "\", \"".join(az_list)
    else:
      return default

  def ec2_vpc_subnets(self, lookup, default=None):
    """
    Args:
      lookup - the friendly name of the VPC whose subnets we want
    Returns:
      A comma-separated list of all subnets in use in the named VPC or default/None if no match found
    """
    vpc_id = self.ec2_vpc_vpc_id(lookup)
    if vpc_id is None:
      return default
    subnets = EFAwsResolver.__CLIENTS["ec2"].describe_subnets(Filters=[{
      'Name': 'vpc-id',
      'Values': [vpc_id]
    }])
    if len(subnets["Subnets"]) > 0:
      # Strip the metadata section (subnets["Subnets"])
      subnet_list = [s["SubnetId"] for s in subnets["Subnets"]]
      # Add internal ", " only. This is called literally from: "{{aws...}}" - reuses the outer quotes
      return "\", \"".join(subnet_list)
    else:
      return default

  def ec2_vpc_cidrblock(self, lookup, default=None):
    """
    Args:
      lookup - the friendly name of the VPC whose CIDR block we want
    Returns:
      The CIDR block of the named VPC, or default/None if no match found
    """
    vpcs = EFAwsResolver.__CLIENTS["ec2"].describe_vpcs(Filters=[{
      'Name': 'tag:Name',
      'Values': [lookup]
    }])
    if len(vpcs.get("Vpcs")) > 0:
      return vpcs["Vpcs"][0]["CidrBlock"]
    else:
      return default

  def ec2_vpc_vpc_id(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of the VPC to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The ID of the first VPC found with a label matching 'lookup' or default/None if no match found
    """
    vpcs = EFAwsResolver.__CLIENTS["ec2"].describe_vpcs(Filters=[{
      'Name': 'tag:Name',
      'Values': [lookup]
    }])
    if len(vpcs.get("Vpcs")) > 0:
      return vpcs["Vpcs"][0]["VpcId"]
    else:
      return default

  def waf_rule_id(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of a WAF rule
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      the ID of the WAF rule whose name matches 'lookup' or default/None if no match found
    """
    # list_rules returns at most 100 rules per request
    list_limit = 100
    rules = EFAwsResolver.__CLIENTS["waf"].list_rules(Limit=list_limit)
    while True:
      for rule in rules["Rules"]:
        if rule["Name"] == lookup:
          return rule["RuleId"]
      if rules.has_key("NextMarker"):
        rules = EFAwsResolver.__CLIENTS["waf"].list_rules(Limit=list_limit, NextMarker=rules["NextMarker"])
      else:
        return default

  def waf_web_acl_id(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of a Web ACL
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      the ID of the WAF Web ACL whose name matches rule_name or default/None if no match found
    """
    # list_rules returns at most 100 rules per request
    list_limit = 100
    acls = EFAwsResolver.__CLIENTS["waf"].list_web_acls(Limit=list_limit)
    while True:
      for acl in acls["WebACLs"]:
        if acl["Name"] == lookup:
          return acl["WebACLId"]
      if acls.has_key("NextMarker"):
        acls = EFAwsResolver.__CLIENTS["waf"].list_web_acls(Limit=list_limit, NextMarker=acls["NextMarker"])
      else:
        return default

  def route53_public_hosted_zone_id(self, lookup, default=None):
    """
    Args:
      lookup: The zone name to look up. Must end with "."
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      the ID of the public hosted zone for the 'lookup' domain, or default/None if no match found
    """
    list_limit = "100"
    # enforce terminal '.' in name, otherwise we could get a partial match of the incorrect zones
    if lookup[-1] != '.':
      return default
    hosted_zones = EFAwsResolver.__CLIENTS["route53"].list_hosted_zones_by_name(DNSName=lookup, MaxItems=list_limit)
    # Return if the account has no HostedZones
    if not hosted_zones.has_key("HostedZones"):
      return default
    while True:
      for hosted_zone in hosted_zones["HostedZones"]:
        if lookup == hosted_zone["Name"] and not hosted_zone["Config"]["PrivateZone"]:
          return hosted_zone["Id"].split("/")[2]
      if hosted_zones["IsTruncated"]:
        hosted_zones = EFAwsResolver.__CLIENTS["route53"].list_hosted_zones_by_name(
          MaxItems=list_limit, Marker=hosted_zones["NextMarker"])
      else:
        return default

  def route53_private_hosted_zone_id(self, lookup, default=None):
    """
    Args:
      lookup: The zone name to look up. Must end with "."
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      the ID of the private hosted zone for the 'lookup' domain, or default/None if no match found
    """
    list_limit = "100"
    # enforce terminal '.' in name, otherwise we could get a partial match of the incorrect zones
    if lookup[-1] != '.':
      return default
    hosted_zones = EFAwsResolver.__CLIENTS["route53"].list_hosted_zones_by_name(DNSName=lookup, MaxItems=list_limit)
    # Return if the account has no HostedZones
    if not hosted_zones.has_key("HostedZones"):
      return default
    while True:
      for hosted_zone in hosted_zones["HostedZones"]:
        if lookup == hosted_zone["Name"] and hosted_zone["Config"]["PrivateZone"]:
          return hosted_zone["Id"].split("/")[2]
      if hosted_zones["IsTruncated"]:
        hosted_zones = EFAwsResolver.__CLIENTS["route53"].list_hosted_zones_by_name(
          MaxItems=list_limit, Marker=hosted_zones["NextMarker"])
      else:
        return default

  def ec2_route_table_main_route_table_id(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of the VPC whose main route table we are looking up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      the ID of the main route table of the named VPC, or None if no match found
    """
    vpc_id = self.ec2_vpc_vpc_id(lookup)
    if vpc_id is None:
      return default
    route_table = EFAwsResolver.__CLIENTS["ec2"].describe_route_tables(Filters=[
      {'Name': 'vpc-id', 'Values': [vpc_id]},
      {'Name': 'association.main', 'Values': ['true']}
    ])
    if len(route_table["RouteTables"]) is not 1:
      return default
    return route_table["RouteTables"][0]["RouteTableId"]

  def cloudfront_domain_name(self, lookup, default=None):
    """
    Args:
      lookup: any CNAME on the Cloudfront distribution
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The domain name (FQDN) of the Cloudfront distrinbution, or default/None if no match
    """
    # list_distributions returns at most 100 distributions per request
    list_limit = "100"
    distributions = EFAwsResolver.__CLIENTS["cloudfront"].list_distributions(MaxItems=list_limit)["DistributionList"]
    # Return if the account has no Distributions
    if not distributions.has_key("Items"):
      return default
    while True:
      for distribution in distributions["Items"]:
        if lookup in distribution["Aliases"]["Items"]:
          return distribution["DomainName"]
      if distributions["IsTruncated"]:
        distributions = EFAwsResolver.__CLIENTS["cloudfront"].list_distributions(
          MaxItems=list_limit, Marker=distributions["NextMarker"])["DistributionList"]
      else:
        return default

  def cloudfront_origin_access_identity_oai_id(self, lookup, default=None):
    """
    Args:
      lookup: the FQDN of the Origin Access Identity (from its comments)
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      the ID of the Origin Access Identity associated with the named FQDN in 'lookup', or default/None if no match
    """
    # list_cloud_front_origin_access_identities returns at most 100 oai's per request
    list_limit = "100"
    oais = EFAwsResolver.__CLIENTS["cloudfront"].list_cloud_front_origin_access_identities(
      MaxItems=list_limit)["CloudFrontOriginAccessIdentityList"]
    # Return if the account has no OriginAccessIdentities
    if not oais.has_key("Items"):
      return default
    while True:
      for oai in oais["Items"]:
        if oai["Comment"] == lookup:
          return oai["Id"]
      if oais["IsTruncated"]:
        oais = EFAwsResolver.__CLIENTS["cloudfront"].list_cloud_front_origin_access_identities(
          MaxItems=list_limit, Marker=oais["NextMarker"])["CloudFrontOriginAccessIdentityList"]
      else:
        return default

  def cloudfront_origin_access_identity_oai_canonical_user_id(self, lookup, default=None):
    """
    Args:
      lookup: the FQDN of the Origin Access Identity (from its comments)
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      the S3 Canonical User ID of the OAI associated with the named FQDN in 'lookup', or default/None if no match
    """
    # list_cloud_front_origin_access_identities returns at most 100 oai's per request
    list_limit = "100"
    oais = EFAwsResolver.__CLIENTS["cloudfront"].list_cloud_front_origin_access_identities(
      MaxItems=list_limit)["CloudFrontOriginAccessIdentityList"]
    # Return if the account has no OriginAccessIdentities
    if not oais.has_key("Items"):
      return default
    while True:
      for oai in oais["Items"]:
        if oai["Comment"] == lookup:
          return oai["S3CanonicalUserId"]
      if oais["IsTruncated"]:
        oais = EFAwsResolver.__CLIENTS["cloudfront"].list_cloud_front_origin_access_identities(
          MaxItems=list_limit, Marker=oais["NextMarker"])["CloudFrontOriginAccessIdentityList"]
      else:
        return default


  def lookup(self, token):
    try:
      kv = token.split(",")
    except ValueError:
      return None
    if kv[0] == "acm:certificate-arn":
      return self.acm_certificate_arn(*kv[1:])
    elif kv[0] == "cloudfront:domain-name":
      return self.cloudfront_domain_name(*kv[1:])
    elif kv[0] == "cloudfront:origin-access-identity/oai-canonical-user-id":
      return self.cloudfront_origin_access_identity_oai_canonical_user_id(*kv[1:])
    elif kv[0] == "cloudfront:origin-access-identity/oai-id":
      return self.cloudfront_origin_access_identity_oai_id(*kv[1:])
    elif kv[0] == "ec2:elasticip/elasticip-id":
      return self.ec2_elasticip_elasticip_id(*kv[1:])
    elif kv[0] == "ec2:elasticip/elasticip-ipaddress":
      return self.ec2_elasticip_elasticip_ipaddress(*kv[1:])
    elif kv[0] == "ec2:eni/eni-id":
      return self.ec2_eni_eni_id(*kv[1:])
    elif kv[0] == "ec2:route-table/main-route-table-id":
      return self.ec2_route_table_main_route_table_id(*kv[1:])
    elif kv[0] == "ec2:security-group/security-group-id":
      return self.ec2_security_group_security_group_id(*kv[1:])
    elif kv[0] == "ec2:subnet/subnet-id":
      return self.ec2_subnet_subnet_id(*kv[1:])
    elif kv[0] == "ec2:vpc/availabilityzones":
      return self.ec2_vpc_availabilityzones(*kv[1:])
    elif kv[0] == "ec2:vpc/cidrblock":
      return self.ec2_vpc_cidrblock(*kv[1:])
    elif kv[0] == "ec2:vpc/subnets":
      return self.ec2_vpc_subnets(*kv[1:])
    elif kv[0] == "ec2:vpc/vpc-id":
      return self.ec2_vpc_vpc_id(*kv[1:])
    elif kv[0] == "route53:private-hosted-zone-id":
      return self.route53_private_hosted_zone_id(*kv[1:])
    elif kv[0] == "route53:public-hosted-zone-id":
      return self.route53_public_hosted_zone_id(*kv[1:])
    elif kv[0] == "waf:rule-id":
      return self.waf_rule_id(*kv[1:])
    elif kv[0] == "waf:web-acl-id":
      return self.waf_web_acl_id(*kv[1:])
    else:
      return None
      # raise("No lookup function for: "+kv[0])


  def __init__(self, clients):
    """
    ARGS
      clients - dictionary of ready-to-go boto3 clients using aws prefixes:
      expected: clients["ec2"], clients["iam"], clients["lambda"]
    """
    EFAwsResolver.__CLIENTS = clients
