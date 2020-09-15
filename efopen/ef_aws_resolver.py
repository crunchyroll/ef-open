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

from __future__ import print_function

import datetime
import re

from botocore.exceptions import ClientError

import ef_utils

class EFAwsResolver(object):
  """
  For keys to look up, we use partial ARN syntax to identify system and information sought:
  http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-ec2
  Not all possible lookups are supported

  Expects these clients to be pre-made and passed in:
    cloudfront, cloudformation, ec2, iam, kms, lambda, route53, waf

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

  def _elbv2_load_balancer(self, lookup):
    """
    Args:
      lookup: the friendly name of the V2 elb to look up
    Returns:
      A dict with the load balancer description
    Raises:
      botocore.exceptions.ClientError: no such load-balancer
    """
    client = EFAwsResolver.__CLIENTS['elbv2']
    elbs = client.describe_load_balancers(Names=[lookup])
    # getting the first one, since we requested only one lb
    elb = elbs['LoadBalancers'][0]
    return elb

  def acm_certificate_arn(self, lookup, default=None):
    """
    Args:
      lookup: region/domain on the certificate to be looked up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      ARN of a certificate with status "Issued" for the region/domain, if found, or default/None if no match
      If more than one "Issued" certificate matches the region/domain:
        - if any matching cert was issued by Amazon, returns ARN of certificate with most recent IssuedAt timestamp
        - if no certs were issued by Amazon, returns ARN of an arbitrary matching certificate
        - certificates issued by Amazon take precedence over certificates not issued by Amazon
    """
    # @todo: Only searches the first 100 certificates in the account

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
    # No certificates
    if len(response["CertificateSummaryList"]) < 1:
      return default
    # One or more certificates - find cert with latest IssuedAt date or an arbitrary cert if none are dated
    best_match_cert = None
    for cert_handle in response["CertificateSummaryList"]:
      if cert_handle["DomainName"] == domain_name:
        cert = acm_client.describe_certificate(CertificateArn=cert_handle["CertificateArn"])["Certificate"]
        # Patch up cert if there is no IssuedAt (i.e. cert was not issued by Amazon)
        if "IssuedAt" not in cert:
          cert[u"IssuedAt"] = datetime.datetime(1970, 1, 1, 0, 0)
        if best_match_cert is None:
          best_match_cert = cert
        elif cert["IssuedAt"] > best_match_cert["IssuedAt"]:
          best_match_cert = cert
    if best_match_cert is not None:
      return best_match_cert["CertificateArn"]
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
    m = re.search('ElasticIp([A-Z]?[a-z]+[0-9]?)\w+', lookup)
    # The lookup string was not a valid ElasticIp resource label
    if m is None:
      return default
    env = m.group(1)
    stackname = "{}-elasticip".format(env.lower())
    # Convert env substring to title in case {{ENV}} substitution is being used
    lookup = lookup.replace(env, env.title())
    # Look up the EIP resource in the stack to get the IP address assigned to the EIP
    try:
      eip_stack = EFAwsResolver.__CLIENTS["cloudformation"].describe_stack_resources(
        StackName=stackname,
        LogicalResourceId=lookup
      )
    except ClientError:
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

  def ec2_network_network_acl_id(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of the network ACL we are looking up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      the ID of the network ACL, or None if no match found
    """
    network_acl_id = EFAwsResolver.__CLIENTS["ec2"].describe_network_acls(Filters=[{
      'Name': 'tag:Name',
      'Values': [lookup]
    }])
    if len(network_acl_id["NetworkAcls"]) > 0:
      return network_acl_id["NetworkAcls"][0]["NetworkAclId"]
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

  def ec2_subnet_subnet_cidr(self, lookup, default=None):
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
      return subnets["Subnets"][0]["CidrBlock"]
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

  def ec2_vpc_endpoint_id(self, lookup, default=None):
    """
    Args:
      lookup: the name of the VPC endpoint to look up (in tags)
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The ID of the VPC Endpoint found with a label matching 'lookup' or default/None if no match found
    """
    vpc_endpoints = EFAwsResolver.__CLIENTS["ec2"].describe_vpc_endpoints(Filters=[{
      "Name": "tag:Name",
      "Values": [lookup]
    }])
    if len(vpc_endpoints.get("VpcEndpoints")) > 0:
      return vpc_endpoints["VpcEndpoints"][0]["VpcEndpointId"]
    else:
      return default

  def ec2_vpc_endpoint_id_by_vpc_service(self, lookup, default=None):
    """
    Args:
      lookup: a forward-slash-delimited string of [vpc-name, service-name] "vpc-name/service-name"
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The ID of the OLDEST VPC endpoint found in the given VPC for the given service
    """
    vpc_name, service_name = lookup.split("/")
    vpc_id = self.ec2_vpc_vpc_id(vpc_name)
    if vpc_id is None:
      return default

    vpc_endpoints = EFAwsResolver.__CLIENTS["ec2"].describe_vpc_endpoints(Filters=[
      {"Name": "vpc-id", "Values":[vpc_id]},
      {"Name": "service-name", "Values":[service_name]}
    ])
    if len(vpc_endpoints.get("VpcEndpoints")) < 1:
      return default

    oldest = None
    for vpce in vpc_endpoints.get("VpcEndpoints"):
      if oldest is None or vpce["CreationTimestamp"] < oldest["CreationTimestamp"]:
        oldest = vpce
    return oldest["VpcEndpointId"]

  def ec2_vpc_endpoint_dns_name(self, lookup, default=None):
    """
    Args:
      lookup: the name of the VPC endpoint to look up (in tags)
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The first DNS Name of the VPC Endpoint found with a label matching 'lookup' or default/None if no match found
    """
    vpc_endpoints = EFAwsResolver.__CLIENTS["ec2"].describe_vpc_endpoints(Filters=[{
      "Name": "tag:Name",
      "Values": [lookup]
    }])
    if len(vpc_endpoints.get("VpcEndpoints")) > 0:
      if len(vpc_endpoints["VpcEndpoints"][0]["DnsEntries"]) < 1:
        return default
      return vpc_endpoints["VpcEndpoints"][0]["DnsEntries"][0]["DnsName"]
    else:
      return default

  def ec2_vpc_endpoint_dns_name_by_vpc_service(self, lookup, default=None):
    """
    Args:
      lookup: a forward-slash-delimited string of [vpc-name, service-name] "vpc-name/service-name"
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The first DNS Name of the OLDEST VPC endpoint found in the given VPC for the given service
    """
    vpc_name, service_name = lookup.split("/")
    vpc_id = self.ec2_vpc_vpc_id(vpc_name)
    if vpc_id is None:
      return default

    vpc_endpoints = EFAwsResolver.__CLIENTS["ec2"].describe_vpc_endpoints(Filters=[
      {"Name": "vpc-id", "Values":[vpc_id]},
      {"Name": "service-name", "Values":[service_name]}
    ])
    if len(vpc_endpoints.get("VpcEndpoints")) < 1:
      return default

    oldest = None
    for vpce in vpc_endpoints.get("VpcEndpoints"):
      if oldest is None or vpce["CreationTimestamp"] < oldest["CreationTimestamp"]:
        oldest = vpce

    if len(oldest["DnsEntries"]) < 1:
      return default
    return oldest["DnsEntries"][0]["DnsName"]

  def ec2_vpc_vpn_gateway_id(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of the VPN Gateway ID to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The ID of the VPN Gateway found with a label matching 'lookup' or default/None if no match found
    """
    vpn_gateways = EFAwsResolver.__CLIENTS["ec2"].describe_vpn_gateways(Filters=[{
      "Name": "tag:Name",
      "Values": [lookup]
    }])
    if len(vpn_gateways) > 0:
      return vpn_gateways["VpnGateways"][0]["VpnGatewayId"]
    else:
      return default

  def elbv2_load_balancer_hosted_zone(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of the V2 elb to look up
      default: value to return in case of no match
    Returns:
      The hosted zone ID of the ELB found with a name matching 'lookup'.
    """
    try:
      elb = self._elbv2_load_balancer(lookup)
      return elb['CanonicalHostedZoneId']
    except ClientError:
      return default

  def elbv2_load_balancer_dns_name(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of the V2 elb to look up
      default: value to return in case of no match
    Returns:
      The hosted zone ID of the ELB found with a name matching 'lookup'.
    """
    try:
      elb = self._elbv2_load_balancer(lookup)
      return elb['DNSName']
    except ClientError:
      return default

  def elbv2_load_balancer_arn_suffix(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of the v2 elb to look up
      default: value to return in case of no match
    Returns:
      The shorthand fragment of the ALB's ARN, of the form `app/*/*`
    """
    try:
      elb = self._elbv2_load_balancer(lookup)
      m = re.search(r'.+?(app\/[^\/]+\/[^\/]+)$', elb['LoadBalancerArn'])
      return m.group(1)
    except ClientError:
      return default

  def elbv2_target_group_arn_suffix(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of the v2 elb target group
      default: value to return in case of no match
    Returns:
      The shorthand fragment of the target group's ARN, of the form
      `targetgroup/*/*`
    """
    try:
      client = EFAwsResolver.__CLIENTS['elbv2']
      elbs = client.describe_target_groups(Names=[lookup])
      elb = elbs['TargetGroups'][0]
      m = re.search(r'.+?(targetgroup\/[^\/]+\/[^\/]+)$', elb['TargetGroupArn'])
      return m.group(1)
    except ClientError:
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
      if "NextMarker" in rules:
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
      if "NextMarker" in acls:
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
    if "HostedZones" not in hosted_zones:
      return default
    while True:
      for hosted_zone in hosted_zones["HostedZones"]:
        if lookup == hosted_zone["Name"] and not hosted_zone["Config"]["PrivateZone"]:
          return hosted_zone["Id"].split("/")[2]
      if hosted_zones["IsTruncated"]:
        hosted_zones = EFAwsResolver.__CLIENTS["route53"].list_hosted_zones_by_name(
          DNSName=hosted_zones["NextDNSName"], HostedZoneId=hosted_zones["NextHostedZoneId"], MaxItems=list_limit)
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
    if "HostedZones" not in hosted_zones:
      return default
    while True:
      for hosted_zone in hosted_zones["HostedZones"]:
        if lookup == hosted_zone["Name"] and hosted_zone["Config"]["PrivateZone"]:
          return hosted_zone["Id"].split("/")[2]
      if hosted_zones["IsTruncated"]:
        hosted_zones = EFAwsResolver.__CLIENTS["route53"].list_hosted_zones_by_name(
          DNSName=hosted_zones["NextDNSName"], HostedZoneId=hosted_zones["NextHostedZoneId"], MaxItems=list_limit)
      else:
        return default

  def ec2_route_table_main_route_table_id(self, lookup, default=None):
    """
    Args:
      lookup: the friendly name of the VPC whose main route table we are looking up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      the ID of the main route table of the named VPC, or default if no match/multiple matches found
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

  def ec2_route_table_tagged_route_table_id(self, lookup, default=None):
    """
    Args:
      lookup: the tagged route table name, should be unique
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      the ID of the route table, or default if no match/multiple matches found
    """
    route_table = EFAwsResolver.__CLIENTS["ec2"].describe_route_tables(Filters=[
      {'Name': 'tag-key', 'Values': ['Name']},
      {'Name': 'tag-value', 'Values': [lookup]}
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
    if "Items" not in distributions:
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
    if "Items" not in oais:
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
    if "Items" not in oais:
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

  def cognito_identity_identity_pool_arn(self, lookup, default=None):
    """
    Args:
        lookup: Cognito Federated Identity name, proto0-cms-identity-pool
        default: the optional value to return if lookup failed; returns None if not set

    Returns:
        the constructed ARN for the cognito identity pool, else default/None
    """
    identity_pool_id = self.cognito_identity_identity_pool_id(lookup, default)

    if identity_pool_id == default:
      return default

    # The ARN has to be constructed because there is no boto3 call that returns the full ARN for a cognito identity pool
    return "arn:aws:cognito-identity:{{{{REGION}}}}:{{{{ACCOUNT}}}}:identitypool/{}".format(identity_pool_id)

  def cognito_identity_identity_pool_id(self, lookup, default=None):
    """
    Args:
        lookup: Cognito Federated Identity name, proto0-cms-identity-pool
        default: the optional value to return if lookup failed; returns None if not set

    Returns:
        the Cognito Identity Pool ID corresponding to the given lookup, else default/None
    """
    # List size cannot be greater than 60
    list_limit = 60
    client = EFAwsResolver.__CLIENTS["cognito-identity"]
    response = client.list_identity_pools(MaxResults=list_limit)

    while "IdentityPools" in response:
      # Loop through all the identity pools
      for pool in response["IdentityPools"]:
        if pool["IdentityPoolName"] == lookup:
          return pool["IdentityPoolId"]

      # No match found on this page, but there are more pages
      if "NextToken" in response:
        response = client.list_identity_pools(MaxResults=list_limit, NextToken=response["NextToken"])
      else:
        break

    return default

  def cognito_idp_user_pool_arn(self, lookup, default=None):
    """
    Args:
        lookup: Cognito User Pool name, proto0-cms-user-pool
        default: the optional value to return if lookup failed; returns None if not set

    Returns:
        the User Pool ARN corresponding to the given lookup, else default/None
    """
    client = EFAwsResolver.__CLIENTS["cognito-idp"]
    user_pool_id = self.cognito_idp_user_pool_id(lookup, default)
    if user_pool_id == default:
      return default

    response = client.describe_user_pool(UserPoolId=user_pool_id)

    if "UserPool" not in response:
      return default

    return response["UserPool"]["Arn"]

  def cognito_idp_user_pool_id(self, lookup, default=None):
    """
    Args:
        lookup: Cognito User Pool name, proto0-cms-user-pool
        default: the optional value to return if lookup failed; returns None if not set

    Returns:
        the User Pool ID corresponding to the given lookup, else default/None
    """
    # List size cannot be greater than 60
    list_limit = 60
    client = EFAwsResolver.__CLIENTS["cognito-idp"]
    response = client.list_user_pools(MaxResults=list_limit)

    while "UserPools" in response:
      # Loop through all user pools
      for pool in response["UserPools"]:
        if pool["Name"] == lookup:
          return pool["Id"]

      # No match found on this page, but there are more pages
      if "NextToken" in response:
        response = client.list_identity_pools(MaxResults=list_limit, NextToken=response["NextToken"])
      else:
        break

    return default

  def kms_decrypt_value(self, lookup):
    """
    Args:
      lookup: the encrypted value to be decrypted by KMS; base64 encoded
    Returns:
      The decrypted lookup value
    """
    decrypted_lookup = ef_utils.kms_decrypt(EFAwsResolver.__CLIENTS["kms"], lookup)
    return decrypted_lookup.plaintext.decode('string_escape')

  def kms_key_arn(self, lookup):
    """
    Args:
      lookup: The key alias, EX: alias/proto0-evs-drm
    Returns:
      The full key arn
    """
    key_arn = ef_utils.kms_key_arn(EFAwsResolver.__CLIENTS["kms"], lookup)
    return key_arn

  def ram_resource_share_arn(self, lookup, default=None):
    """
    Args:
      lookup: the name of the resource share to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The arn of the first resource share found with a label matching 'lookup' or default/None if no match found
    """
    resource_shares = EFAwsResolver.__CLIENTS["ram"].get_resource_shares(
      resourceOwner="OTHER-ACCOUNTS",
      name=lookup)

    if len(resource_shares.get("resourceShares")) > 0:
      return resource_shares["resourceShares"][0]["resourceShareArn"]
    else:
      return default

  def ram_resource_arn(self, lookup, default=None):
    """
    Args:
      lookup: the resource share arn to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The arn of the first resource found with a label matching 'lookup' or default/None if no match found
    """
    resources = EFAwsResolver.__CLIENTS["ram"].list_resources(
      resourceOwner="OTHER-ACCOUNTS",
      resourceShareArns=[lookup])

    if len(resources.get("resources")) > 0:
      return resources["resources"][0]["arn"]
    else:
      return default

  def ec2_transit_gateway_id(self, lookup, default=None):
    """
    Args:
      lookup: the arn of the transit gateway to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The id of the first transit gateway found with a label matching 'lookup' or default/None if no match found
    """
    transit_gateways = EFAwsResolver.__CLIENTS["ec2"].describe_transit_gateways()

    if len(transit_gateways.get("TransitGateways")) > 0:
      transit_gateways = [i for i in transit_gateways["TransitGateways"] if (i["TransitGatewayArn"] == lookup)]
      return transit_gateways[0]["TransitGatewayId"]
    else:
      return default

  def ecr_repository_uri(self, lookup, default=None):
    """
    Args:
      lookup: the name of the Docker image to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The id of the first image found with a label matching 'lookup' or default/None if no match found
    """
    try:
      repositories = EFAwsResolver.__CLIENTS["ecr"].describe_repositories(repositoryNames=[ lookup ])
      if len(repositories.get("repositories")) > 0:
        return repositories.get("repositories")[0]["repositoryUri"]
      else:
        return default
    except ClientError:
      return default

  def dynamodb_stream_arn(self, lookup, default=None):
    """
    Args:
      lookup: the name of the DynamoDB table to look up
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The DynamoDB Stream ARN with a label matching 'lookup' or default/None if no match found
    """
    try:
      dynamodb_table = EFAwsResolver.__CLIENTS["dynamodb"].describe_table(TableName=lookup)
      if dynamodb_table:
        return dynamodb_table["Table"]["LatestStreamArn"]
      else:
        return default
    except ClientError:
      return default

  def lookup(self, token):
    try:
      kv = token.split(",")
    except (ValueError, AttributeError):
      return None
    if kv[0] == "acm:certificate-arn":
      return self.acm_certificate_arn(*kv[1:])
    elif kv[0] == "cloudfront:domain-name":
      return self.cloudfront_domain_name(*kv[1:])
    elif kv[0] == "cloudfront:origin-access-identity/oai-canonical-user-id":
      return self.cloudfront_origin_access_identity_oai_canonical_user_id(*kv[1:])
    elif kv[0] == "cloudfront:origin-access-identity/oai-id":
      return self.cloudfront_origin_access_identity_oai_id(*kv[1:])
    elif kv[0] == "cognito-identity:identity-pool-arn":
      return self.cognito_identity_identity_pool_arn(*kv[1:])
    elif kv[0] == "cognito-identity:identity-pool-id":
      return self.cognito_identity_identity_pool_id(*kv[1:])
    elif kv[0] == "cognito-idp:user-pool-arn":
      return self.cognito_idp_user_pool_arn(*kv[1:])
    elif kv[0] == "cognito-idp:user-pool-id":
      return self.cognito_idp_user_pool_id(*kv[1:])
    elif kv[0] == "dynamodb:stream-arn":
      return self.dynamodb_stream_arn(*kv[1:])
    elif kv[0] == "ec2:elasticip/elasticip-id":
      return self.ec2_elasticip_elasticip_id(*kv[1:])
    elif kv[0] == "ec2:elasticip/elasticip-ipaddress":
      return self.ec2_elasticip_elasticip_ipaddress(*kv[1:])
    elif kv[0] == "ec2:eni/eni-id":
      return self.ec2_eni_eni_id(*kv[1:])
    elif kv[0] == "ec2:network/network-acl-id":
      return self.ec2_network_network_acl_id(*kv[1:])
    elif kv[0] == "ec2:route-table/main-route-table-id":
      return self.ec2_route_table_main_route_table_id(*kv[1:])
    elif kv[0] == "ec2:route-table/tagged-route-table-id":
      return self.ec2_route_table_tagged_route_table_id(*kv[1:])
    elif kv[0] == "ec2:security-group/security-group-id":
      return self.ec2_security_group_security_group_id(*kv[1:])
    elif kv[0] == "ec2:subnet/subnet-cidr":
      return self.ec2_subnet_subnet_cidr(*kv[1:])
    elif kv[0] == "ec2:subnet/subnet-id":
      return self.ec2_subnet_subnet_id(*kv[1:])
    elif kv[0] == "ec2:transit-gateway/transit-gateway-id":
      return self.ec2_transit_gateway_id(*kv[1:])
    elif kv[0] == "ec2:vpc/availabilityzones":
      return self.ec2_vpc_availabilityzones(*kv[1:])
    elif kv[0] == "ec2:vpc/cidrblock":
      return self.ec2_vpc_cidrblock(*kv[1:])
    elif kv[0] == "ec2:vpc/subnets":
      return self.ec2_vpc_subnets(*kv[1:])
    elif kv[0] == "ec2:vpc/vpc-id":
      return self.ec2_vpc_vpc_id(*kv[1:])
    elif kv[0] == "ec2:vpc-endpoint/vpc-endpoint-id":
      return self.ec2_vpc_endpoint_id(*kv[1:])
    elif kv[0] == "ec2:vpc-endpoint/vpc-endpoint-id/by-vpc-service":
      return self.ec2_vpc_endpoint_id_by_vpc_service(*kv[1:])
    elif kv[0] == "ec2:vpc-endpoint/dns-name":
      return self.ec2_vpc_endpoint_dns_name(*kv[1:])
    elif kv[0] == "ec2:vpc-endpoint/dns-name/by-vpc-service":
      return self.ec2_vpc_endpoint_dns_name_by_vpc_service(*kv[1:])
    elif kv[0] == "ec2:vpc/vpn-gateway-id":
      return self.ec2_vpc_vpn_gateway_id(*kv[1:])
    elif kv[0] == "ecr:repository/repository-uri":
      return self.ecr_repository_uri(*kv[1:])
    elif kv[0] == "elbv2:load-balancer/dns-name":
      return self.elbv2_load_balancer_dns_name(*kv[1:])
    elif kv[0] == "elbv2:load-balancer/hosted-zone":
      return self.elbv2_load_balancer_hosted_zone(*kv[1:])
    elif kv[0] == "elbv2:load-balancer/arn-suffix":
      return self.elbv2_load_balancer_arn_suffix(*kv[1:])
    elif kv[0] == "elbv2:target-group/arn-suffix":
      return self.elbv2_target_group_arn_suffix(*kv[1:])
    elif kv[0] == "kms:decrypt":
      return self.kms_decrypt_value(*kv[1:])
    elif kv[0] == "kms:key_arn":
      return self.kms_key_arn(*kv[1:])
    elif kv[0] == "ram:resource-share/resource-share-arn":
      return self.ram_resource_share_arn(*kv[1:])
    elif kv[0] == "ram:resource-share/resource-arn":
      return self.ram_resource_arn(*kv[1:])
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
