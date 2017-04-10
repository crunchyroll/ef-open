## What does the ellation_formation ef-cf tool do?

The main difference in CF templating with {{SYMBOLS}}...

We switch from this non-human-readable, manually-looked-up form (for example, to refer to a security group):

`"GroupId": "sg-803a8e34"`

... to this human-readable, machine-looked-up form:

```"GroupId": "{{aws:ec2:security-group/security-group-id,{{ENV}}-ess-elb}}"```

The above ```{{aws:ec2:...}}``` lookup returns the Security Group ID of the load balancer for the ess service
in the current environment.

### Syntax in CloudFormation templates, in general
```{{<symbol_name>[,lookup][,default]}}```

#### Examples
- ```{{ENV}}```
- ```{{aws:ec2:vpc/availabilityzones,vpc-{{ENV}}}}```
- ```{{aws:route53:public-hosted-zone-id,cx-{{ENV}}.com.}}```
- ```{{aws:route53:public-hosted-zone-id,cx-{{ENV}}.com.,somedefaultdomain.com.}}```

#### Defaults
- If a \<default> value is present, and the lookup fails, the default value is used.
- If a \<default> value is not present and the lookup fails, the symbol will remain
unresolved and processing will stop with an error (ef-cf won't upload a template with unresolved symbols)

Default values should be used sparingly. They are mostly used to pass syntax checks for values gated by Condition statements in the template, since the symbol must resolve even if the condition is false.

##### Example of a default value in a symbol lookup, guarded by a CloudFormation conditional
```
"AcmCertificateArn" : { "Fn::If": [
  "EnvIsProd",
    "{{aws:acm:certificate-arn,us-east-1/mydomain.co,NONE}}",
    "{{aws:acm:certificate-arn,us-east-1/myotherdomain-{{ENV}}.com,NONE}}"
  ]
},
```

### Replace Fn::Join with inline symbol lookups makes them easier to read

If you formerly wrote this, with EnvParam coming in from a parameters file:
```
"BucketName": { "Fn::Join": [ "-", [ "ellation-cx", { "Ref": "EnvParam" }, "s3logs" ] ] },
```
... rewrite it like this and remove EnvParam from the parameter file
```
"BucketName": "ellation-cx-{{ENV}}-s3logs",
```

## Symbols for CloudFormation templates deployed with ef-cf:
When used in a CF template, lookup symbols are wrapped in double braces, like this: {{ENV}}

The symbol names are derived from the AWS ARN syntax. We start with the objects at
http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-ec2, but remove "arn", "
\<region>", and "\<account>:" to create query keys.


| Symbol name	| What it contains | Example(s) |
| ----------- | ---------------- | ---------- |
| <b>Instance / Service Context</b> | | |
| {{ACCOUNT}} | numeric account the stack is being deployed into | 0123456789012 |
| {{ACCOUNT_ALIAS}} | alphanumeric alias of {{ACCOUNT}}	| myaccountalias |
| {{ENV}} | environment the stack is being built in	| staging<br>proto3 |
| {{ENV_FULL}} | fully qualified name of the environment including ".account" for global (only for a short while longer) and mgmt environments | prod<br>staging<br>proto0<br>global.myaccountalias<br>global.myaccountalias2 |
| {{ENV_SHORT}} | short version of {{ENV}} if it has a numeric suffix	staging | proto |
| {{SERVICE}} | name of the service being deployed | vod-origin |
| {{REGION}} | region being deployed into | us-west-2 |
| <b>AWS resources</b> | What it needs<br>What it returns | Example lookup<br>Example return|
| {{aws:acm:certificate-arn,<region>/<domain_name>}}<br>

example:
aws:acm:certificate-arn,us-west-2/cx-proto3.com | Region and main domain name on certificate<br>
ARN of the ISSUED certificate for that domain, if there is one. Certificates whose status is not "ISSUED" are not returned |
us-west-2/cx-proto3.com<br>arn:aws:acm:us-west-2:366843697376:certificate/acf5ef38-1948-4e62-b6ab-28f54d4a3fe9 |
aws:cloudfront:domain-name,<cname>
example:
aws:cloudfront:domain-name,static.cx-{{ENV}}.com
which is looked up in 'proto3' as:
aws:cloudfront:domain-name,static.cx-proto3.com
Any of the CNAMEs on the CloudFront distribution
Domain Name of the distribution that hosts that CNAME
static.cx-proto3.com
d6wsamxysrvr4.cloudfront.net
aws:cloudfront:origin-access-identity/oai-canonical-user-id,<oai_fqdn>
example:
aws:cloudfront:origin-access-identity/oai-canonical-user-id,static.cx-{{ENV}}.com
which is looked up in 'proto3' as:
aws:cloudfront:origin-access-identity/oai-id,static.cx-proto3.com
FQDN that the Origin Access Identity (OAI) is associated with. When we create an OAI, we add a comment that identifies the domain that it's for. The comment is what's used for the lookup.
ID of the Amazon S3 Canonical User ID associated with the FQDN
static.cx-proto3.com
ada42644cade...
aws:cloudfront:origin-access-identity/oai-id,<oai_fqdn>
example:
aws:cloudfront:origin-access-identity/oai-id,static.cx-{{ENV}}.com
which is looked up in 'proto3' as:
aws:cloudfront:origin-access-identity/oai-id,static.cx-proto3.com
FQDN that the Origin Access Identity (OAI) is associated with. When we create an OAI, we add a comment that identifies the domain that it's for. The comment is what's used for the lookup.
ID of the Origin Access Identity associated with the FQDN
static.cx-proto3.com
E3P54S8TLL883D
aws:ec2:elasticip/elasticip-id,<elasticip_resourceid>
example:
aws:ec2:elasticip/elasticip-id,ElasticIpMgmtCingest1
Resource names for Elastic IPs in the elasticip.json fixture template follow a strict convention. If the convention is not followed, lookups will not work.
See Elastic IPs for Fixed IP Addresses in the Network Runbook

Resource ID of the Elastic IP as written in the elasticip.json fixture template (and thus in the CF stack)
Allocation ID of the Elastic IP whose resource ID is <elasticip_resourceid>
ElasticIpMgmtCingest1
eipalloc-a557dcc2
aws:ec2:elasticip/elasticip-ipaddress,<elasticip_resourceid>
example:
aws:ec2:elasticip/elasticip-ipaddress,ElasticIpMgmtCingest1
Resource names for Elastic IPs in the elasticip.json fixture template follow a strict convention. If the convention is not followed, lookups will not work.
See Elastic IPs for Fixed IP Addresses in the Network Runbook
Resource ID of the Elastic IP as written in the elasticip.json fixture template (and thus in the CF stack)
Public IP address of the Elastic IP whose resource ID is <elasticip_resourceid>
ElasticIpMgmtCingest1
35.161.255.167
aws:ec2:eni/eni-id,<eni_description>
pattern:
aws:ec2:eni/eni-id,eni-{{ENV}}-{{SERVICE}}-<N><subnet_letter>
interface '1' in subnet 'a' in env 'proto3' for the 'dnsproxy' service is looked up as:
aws:ec2:eni/eni-id,eni-proto3-dnsproxy-1a
"Description" field of the Elastic Network Interface to be looked up. ENIs are defined in the network.json fixture; their descriptions should follow the standard format shown at left.
ID of the Elastic Network Interface having the <eni_description>
eni-proto3-dnsproxy-1a
eni-33df0a2b
aws:ec2:route-table/main-route-table-id,<vpc_name>
Friendly name of the VPC containing the main route table, always "vpc-<env>"
Route table's ID
vpc-prod
rtb-3f820be9a
aws:ec2:security-group/security-group-id,<sg_friendly_name>
example:
aws:ec2:security-group/security-group-id,{{ENV}}-ess
which is looked up in 'proto3' as:
aws:ec2:security-group/security-group-id,proto3-ess
Security group's friendly name
Security group ID
staging-ess
sg-78fe34a6
aws:ec2:subnet/subnet-id,<subnet_friendly_name>
example:
aws:ec2:subnet/subnet-id,subnet-{{ENV}}-a
which is looked up in 'proto3' as:
aws:ec2:subnet/subnet-id,subnet-proto3-a
Subnet's friendly name, which is always "subnet-<env>-a" or "subnet-<env>-b"
Subnet's ID
subnet-staging-a
subnet-ad8f55c9
aws:ec2:vpc/cidrblock,<vpc_friendly_name>
example:
aws:ec2:vpc/cidrblock,<vpc_name>
which is looked up in 'proto3' as:
aws:ec2:vpc/cidrblock,vpc-proto3
VPC's friendly name, which is always "vpc-<env>"
VPC's CIDR block
vpc-staging
10.8.64.0/18
aws:ec2:vpc/vpc-id,<vpc_friendly_name>
example:
aws:ec2:vpc/vpc-id,vpc-{{ENV}}
which is looked in 'proto3' as:
aws:ec2:vpc/vpc-id,vpc-proto3
VPC's friendly name, which is always "vpc-<env>"
VPC's ID
vpc-prod
vpc-65ef1239
aws:ec2:vpc/availabilityzones,<vpc_friendly_name>
Usage example
Use exactly like this in the template, including [ ] and dual quotes
"AvailabilityZones": [ "{{aws:ec2:vpc/availabilityzones,vpc-{{ENV}}}}" ]
Friendly name of the VPC serving the target environment, which is always "vpc-<env>"
Comma-separated list of availability zones that contain subnets within the VPC, with internal double-quotes (external double-quotes come from the template)
vpc-staging
"us-west-2a","us-west-2b"
aws:ec2:vpc/subnets,<vpc_friendly_name>
Usage example
Use exactly like this in the template, including [ ] and dual quotes
"Subnets": [ "{{aws:ec2:vpc/subnets,vpc-{{ENV}}}}" ]
Friendly name of the vpc serving the target environment, which is always "vpc-<env>"
Comma-separated list of all subnet IDs within the VPC, with internal double-quotes (external double-quotes come from the template)
vpc-staging
"subnet-dda956ab","subnet-ad8f55c9"
aws:route53:private-hosted-zone-id,<zone_name>.
example:
aws:route53:private-hosted-zone-id,cx-proto3.
fully qualified private zone name, ending with "."
Private Zone's ID in Route53
cx-staging.
Z2ASVW53V915EN
aws:route53:public-hosted-zone-id,<zone_name>.
example:
aws:route53:public-hosted-zone-id,cx-proto3.
fully qualified public zone name, ending with "."
Public Zone's ID in Route53
cx-staging.
Z3RSER33V9W3RN
aws:waf:rule-id,<waf_rule_name>
example:
aws:waf:rule-id,global-OfficeCidr
friendly name of the WAF rule
WAF rule's ID
global-officeCidr
e87a80f6-50b6-...
aws:waf:web-acl-id,<web_acl_name>
example:
aws:waf:web-acl-id,staging-StaticAcl
friendly name of the WAF rule
WAF rule's ID
staging-StaticAcl
e87a80f6-50b6-...
EFConfig lookup symbols	What it needs
What it returns 	Example
efconfig:accountaliasofenv,<env>
example:
efconfig:accountaliasofenv,staging
The ID of the configuration value to be looked up
A value from the EFConfig constants that control ef tools
staging
ellationeng
Version lookup symbols
What it needs
What it returns
Example
version:ami-id,<service_name>
example:
version:ami-id,ess
The ID of the designated AMI for the target environment
ess
ami-abcd0123


Examples of the various forms of "ENV" in templates and how they resolve
Environment	Account	ENV Resolves to	ENV_SHORT resolves to	ENV_FULL resolves to
prod	N/A	prod	prod	prod
staging	N/A	staging	staging	staging
proto0
proto<1..N> 	N/A	proto0
proto1..N 	proto
proto 	proto0
proto<1..N>
global	ellation	global	global	global.ellation
global	ellationeng	global	global	global.ellationeng
internal	ellationint	internal	internal	internal.ellationint
mgmt	ellation	mgmt	mgmt	mgmt.ellation
mgmt	ellationeng	mgmt	mgmt
mgmt.ellationeng
