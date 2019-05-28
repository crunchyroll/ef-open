#!/usr/bin/env python

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

from ef_template_resolver import EFTemplateResolver
from ef_conf_utils import get_account_alias

PARAMS = """{
  "params":{
    "default":{
      "address": "default address",
      "phone": "default phone",
      "ACC": "ACC",
      "OUNT": "OUNT",
      "/_-.": "slashunderscoredashdot",
      "illegal": "cannot have a comma",
      ".": "dot",
      "my-thing": "my-thing",
      "multi-line-thing": "line1\\nline2\\nline3\\nline4",
      "multi-line-thing-2": [
        "first thing",
        "second thing"
      ]
    },
    "proto":{
      "blah": "this text should only print if env is protoN",
      "name": "proto name"
    },
    "proto3":{
      "name": "proto3 name",
      "address": "proto3 address",
      "ENV": "this should never print"
    },
    "staging": {
      "name": "staging name"
    }
  }
}
"""

LOCAL = True

TEST_STRING = "name: {{name}} address:{{address}} phone:{{phone}}?\n \
account:{{ACCOUNT}},\n \
nested account:{{{{ACC}}{{OUNT}}}}, env:{{ENV}},\n \
fully-qualified environment:{{ENV_FULL}},\n \
region:{{REGION}},\n \
special characters:{{/_-.}},\n \
dot:{{.}},\n\
general 'proto' token only if env is protoN: {{blah}}\n \
and this {{DOESNOTRESOLVE}} and {{neitherdoesthis}}\n\
and {{this is not a symbol}} and {{thisisalsonotasymbol?!}}\n\
hyphenated symbol name: {{my-thing}}\n\
aws security group lookup: {{aws:ec2:security-group/security-group-id,proto2-core-elb}}\n\
aws lookup AZs of staging env via vpc+subnets: {{aws:ec2:vpc/availabilityzones,vpc-staging}}\n\
aws lookup AZs of proto3 env via vpc+subnets: {{aws:ec2:vpc/availabilityzones,vpc-proto3}}\n\
aws lookup subnets of staging env via vpc: {{aws:ec2:vpc/subnets,vpc-staging}}\n\
aws lookup subnets of proto3 env via vpc: {{aws:ec2:vpc/subnets,vpc-proto3}}\n\
aws lookup subnets of the current env '{{ENV}}' via vpc: {{aws:ec2:vpc/subnets,vpc-{{ENV}}}}\n\
multi-line:\n\
{{multi-line-thing}}\n\
\"{{multi-line-thing-2}}\"\n\
Subnets: [ \"{{aws:ec2:vpc/subnets,vpc-staging}}\" ]\n\
Single-subnet lookup, subnet-proto3-a: {{aws:ec2:subnet/subnet-id,subnet-{{ENV}}-a}}\n\
WAF Rule ID lookup: {{aws:waf:rule-id,global-OfficeCidr}}\n\
Public Hosted Zone lookup: {{aws:route53:public-hosted-zone-id,cx-proto3.com.}}\n\
Private Hosted Zone lookup: {{aws:route53:private-hosted-zone-id,cx-proto3.com.}}\n\
Route table lookup: {{aws:ec2:route-table/main-route-table-id,vpc-proto0}}\n\
Cloudfront distribution Domain Name: {{aws:cloudfront:domain-name,api.cx-proto3.com}}\n\
Cloudfront Origin Access Identity ID lookup: \
{{aws:cloudfront:origin-access-identity/oai-id,static.cx-proto3.com}}\n\
Cloudfront Origin Access Identity Canonical User ID lookup: \
{{aws:cloudfront:origin-access-identity/oai-canonical-user-id,static.cx-proto3.com}}\n\
VPC CIDR block: {{aws:ec2:vpc/cidrblock,vpc-staging}}\n\
WAF Web ACL ID: {{aws:waf:web-acl-id,staging-StaticAcl}}\n\
SSL Certificate ARN us-west-2/cx-proto3.com: {{aws:acm:certificate-arn,us-west-2/cx-proto3.com}}\n\
Elastic network interface (ENI) eni-proto0-dnsproxy-1a: {{aws:ec2:eni/eni-id,eni-proto0-dnsproxy-1a}}\n\
Elastic IP Allocation ID: {{aws:ec2:elasticip/elasticip-id,ElasticIpMgmtCingest1}}\n\
Elastic IP IP Address: {{aws:ec2:elasticip/elasticip-ipaddress,ElasticIpMgmtCingest1}}\n\
EFConfig resolver, accountaliasofenv,prod: {{efconfig:accountaliasofenv,staging}}\n\
AMI lookup: {{version:ami-id,proto0/test-instance}}\n\
Latest AMI for test-instance: {{version:ami-id,proto0/test-instance}}\n\
Custom Data: \"{{efconfig:customdata,office_ips}}\"\
"

GLOBAL_ENV_TEST_STRING = "fully-qualified environment:{{ENV_FULL}}\n"

# Test with proto0
if LOCAL:
  resolver = EFTemplateResolver(profile=get_account_alias("proto0"), env="proto0", region="us-west-2",
                                service="mine", verbose=True)
else:
  resolver = EFTemplateResolver(verbose=True)

resolver.load(TEST_STRING, PARAMS)
resolver.render()

print(resolver.template)
print("unresolved symbol count: "+str(len(resolver.unresolved_symbols())))
print("unresolved symbols: "+repr(resolver.unresolved_symbols()))
print("all template symbols: "+repr(resolver.symbols))
print("all EFTemplateResolver symbols: "+repr(resolver.resolved))


# Demo with the global env 'mgmt.ellationeng' (local only)
if LOCAL:
  resolver = EFTemplateResolver(profile=get_account_alias("mgmt.ellationeng"), env="mgmt.ellationeng", region="us-west-2",
                                service="mine", verbose=True)

  resolver.load(GLOBAL_ENV_TEST_STRING, PARAMS)
  resolver.render()

  print("\nDemo 'mgmt.ellationeng' resolution")
  print(resolver.template)
  print("unresolved symbol count: "+str(len(resolver.unresolved_symbols())))
  print("unresolved symbols: "+repr(resolver.unresolved_symbols()))
  print("all template symbols: "+repr(resolver.symbols))
  print("all EFTemplateResolver symbols: "+repr(resolver.resolved))
