## What does the ellation_formation ef-cf tool do?

The main difference in CF templating with {{SYMBOLS}}...

We switch from this non-human-readable, manually-looked-up form (for example, to refer to a security group):

`"GroupId": "sg-803a8e34"`

... to this human-readable, machine-looked-up form:

```"GroupId": "{{aws:ec2:security-group/security-group-id,{{ENV}}-myservice-elb}}"```

The above ```{{aws:ec2:...}}``` lookup returns the Security Group ID of the load balancer for the ess service
in the current environment.

### Syntax in CloudFormation templates, in general
```{{<symbol_name>[,lookup][,default]}}```

#### Defaults
- If a \<default> value is present, and the lookup fails, the default value is used.
- If a \<default> value is not present and the lookup fails, the symbol will remain
unresolved and processing will stop with an error (ef-cf won't upload a template with unresolved symbols)

Default values should be used sparingly. They are mostly used to pass syntax checks for values gated by Condition statements in the template, since the symbol must resolve even if the condition is false.

### Examples
- ```{{ENV}}```
- ```{{aws:ec2:vpc/availabilityzones,vpc-{{ENV}}}}```
- ```{{aws:route53:public-hosted-zone-id,mydomain-{{ENV}}.com.}}```
- ```{{aws:route53:public-hosted-zone-id,mydomain-{{ENV}}.com.,somedefaultdomain.com.}}```

##### Bigger example: a default value in a symbol lookup, guarded by a CloudFormation conditional
```
"AcmCertificateArn" : { "Fn::If": [
  "EnvIsProd",
    "{{aws:acm:certificate-arn,us-east-1/mydomain.com,NONE}}",
    "{{aws:acm:certificate-arn,us-east-1/myotherdomain-{{ENV}}.com,NONE}}"
  ]
},
```

### Protips
#### Replace Fn::Join with inline symbol lookups to make the template human-auditable
If you formerly wrote this, with EnvParam coming in from a parameters file:
```
"BucketName": { "Fn::Join": [ "-", [ "mydomain", { "Ref": "EnvParam" }, "s3logs" ] ] },
```
... rewrite it like this and remove EnvParam from the parameter file
```
"BucketName": "mydomain-{{ENV}}-s3logs",
```

## Symbols for CloudFormation templates deployed with ef-cf:
When used in a CF template, lookup symbols are wrapped in double braces, like this: {{ENV}}

The symbol names are derived from the AWS ARN syntax. We start with the objects at
http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-ec2, but remove "arn", "
\<region>", and "\<account>:" to create query keys.


### Instance / Service Context
| Symbol name	| What it contains | Example(s) |
| ----------- | ---------------- | ---------- |
| ```{{ACCOUNT}}``` | numeric account the stack is being deployed into | 0123456789012 |
| ```{{ACCOUNT_ALIAS}}``` | alphanumeric alias of ```{{ACCOUNT}}```	| myaccountalias |
| ```{{ENV}}``` | environment the stack is being built in	| staging<br>proto3 |
| ```{{ENV_FULL}}``` | fully qualified name of the environment including ".account" for global (only for a short while longer) and mgmt environments | prod<br>staging<br>proto0<br>global.myaccountalias<br>global.myaccountalias2 |
| ```{{ENV_SHORT}}``` | short version of {{ENV}} if it has a numeric suffix	staging | proto |
| ```{{SERVICE}}``` | name of the service being deployed | vod-origin |
| ```{{REGION}}``` | region being deployed into | us-west-2 |

### AWS Resources

#### {{aws:acm:certificate-arn,\<region>/<domain_name>}}
Returns: ARN of the ISSUED certificate for a domain in AWS Certificate Manager, if there is one. Certificates whose status is not "ISSUED" are not returned<br>
Needs: Region and main domain name on certificate<br>
Example:<br>
```{{aws:acm:certificate-arn,us-west-2/mydomain.com}}```<br>
```arn:aws:acm:us-west-2:0123456789012:certificate/abcdef01-0123-abcd-0123-01234567890a```
 
#### {{aws:cloudfront:domain-name,\<cname>}}
Returns: Domain name of the CloudFront distribution that hosts a given CNAME<br>
Needs: Any domain name that's a CNAME on the desired CLoudFront distribution<br>
Example:<br>
```{{aws:cloudfront:domain-name,static.mydomain-{{ENV}}.com}}```<br>
which is looked up in env "proto3" as:<br>
```{{aws:cloudfront:domain-name,static.mydomain-proto3.com}}```<br>
returning:<br>
```d6mwasxvryve1.cloudfront.net```

#### {{aws:cloudfront:origin-access-identity/oai-canonical-user-id,<oai_fqdn>}}
Returns: Amazon S3 Canonical User ID associated with an Origin Access Identity (identified by the comment on the OAI, which for us is always a FQDN) FQDN<br>
Needs: FQDN that the Origin Access Identity (OAI) is associated with. When we create an OAI, we add a comment that identifies the domain that it's for. The comment is what's used for the lookup.<br>
Note: In our process, the "Comment" on the OAI is literally the FQDN, e.g.: "static.mydomain-proto3.com"<br>
Example:<br>
```{{aws:cloudfront:origin-access-identity/oai-canonical-user-id,static.mydomain-{{ENV}}.com}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:cloudfront:origin-access-identity/oai-canonical-user-id,static.mydomain-proto3.com```<br>
returning:<br>
```c1dabc158c3cca7db15d511cbe6661319ae8111d56b113ab751411171a51e16e9baa7d1d4e4c8a1b9363c4111bdad4a7```

#### {{aws:cloudfront:origin-access-identity/oai-id,<oai_fqdn>}}
Returns: ID of the Origin Access Identity associated with the FQDN (identified by the comment on the OAI, which for us is always a FQDN) FQDN<br>
Needs: FQDN that the Origin Access Identity (OAI) is associated with. When we create an OAI, we add a comment that identifies the domain that it's for. The comment is what's used for the lookup.<br>
Note: In our process, the "Comment" on the OAI is literally the FQDN, e.g.: "static.mydomain-proto3.com"<br>
Example:<br>
```{{aws:cloudfront:origin-access-identity/oai-id,static.mydomain-{{ENV}}.com}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:cloudfront:origin-access-identity/oai-id,static.mydomain-proto3.com```<br>
returning:<br>
```A2Q53T2TMX231E```

#### {{aws:ec2:elasticip/elasticip-id,<elasticip_resourceid>}}
Returns: Allocation ID of the Elastic IP whose resource ID is <elasticip_resourceid><br>
Needs: Resource ID of the Elastic IP (and thus in the CF stack)<br>
Note: in our process, the Resource ID is set in the elasticip.json fixture template, and is composed as: "ElasticIP\<ENV>\<SERVICE>"<br>
Example:<br>
```{{aws:ec2:elasticip/elasticip-id,ElasticIpMgmtMyService1}}```<br>
Returns:<br>
```eipalloc-b351cab5```<br>

#### {{aws:ec2:elasticip/elasticip-ipaddress,<elasticip_resourceid>}}
Returns: Public IP address of the Elastic IP whose resource ID is \<elasticip_resourceid><br>
Needs: Resource ID of the Elastic IP (and thus in the CF stack)<br>
Note: in our process, the Resource ID is set in the elasticip.json fixture template, and is composed as: "ElasticIP\<ENV>\<SERVICE>"<br>
Example:<br>
```{{aws:ec2:elasticip/elasticip-ipaddress,ElasticIpMgmtMyService1}}```<br>
Returns:<br>
```35.161.255.167```<br>

#### {{aws:ec2:eni/eni-id,<eni_description>}}
Returns: ID of the Elastic Network Interface having the <eni_description><br>
Needs: "Description" field of the Elastic Network Interface to be looked up.
Note: In our process, the Description field of an ENI is composed as:<br>
```eni-{{ENV}}-{{SERVICE}}-<N><subnet_letter><br>```
pattern:<br>
```aws:ec2:eni/eni-id,eni-{{ENV}}-{{SERVICE}}-<N><subnet_letter>```<br>
Example:<br>
interface '1' in subnet 'a' in env 'proto3' for the 'myservice' service is looked up as:<br>
```aws:ec2:eni/eni-id,eni-proto3-myservice-1a```
Returns:<br>
```eni-31ca3f1a```

#### {{aws:ec2:route-table/main-route-table-id,<vpc_name>}}
Returns: Route table ID<br>
Needs: Friendly name of the VPC containing the main route table, always "vpc-\<env>"<br>
Example:<br>
```{{aws:ec2:route-table/main-route-table-id,vpc-{{ENV}}}}```<br>
which is looked up in 'prod' as:<br>
```{{aws:ec2:route-table/main-route-table-id,vpc-prod}}```<br>
returning:<br>
```rtb-3f820be9a```<br>

#### {{aws:ec2:security-group/security-group-id,<sg_friendly_name>}}
Returns: Security group ID<br>
Needs: Security group's friendly name<br>
Example:<br>
```{{aws:ec2:security-group/security-group-id,{{ENV}}-myservice}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:ec2:security-group/security-group-id,proto3-myservice}}```<br>
returning:<br>
```sg-78fe34a6```<br>

#### {{aws:ec2:subnet/subnet-id,<subnet_friendly_name>}}
Returns: subnet ID<br>
Needs: Subnet's friendly name, which is always "subnet-\<env>-\<az>"<br>
Example:<br>
```{{aws:ec2:subnet/subnet-id,subnet-{{ENV}}-a}}```<br>
which is looked up in 'proto3' as:
```{{aws:ec2:subnet/subnet-id,subnet-proto3-a}}```<br>
returning:<br>
```subnet-be2d211a```<br>

#### {{aws:ec2:vpc/cidrblock,<vpc_friendly_name>}}
Returns: VPC's CIDR block<br>
Needs: VPC's friendly name, which is always "vpc-\<env>"<br>
Example:<br>
```{{aws:ec2:vpc/cidrblock,<vpc_name>}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:ec2:vpc/cidrblock,vpc-proto3}}```<br>
returning:<br>
```10.8.64.0/18```<br>

#### {{aws:ec2:vpc/vpc-id,<vpc_friendly_name>}}
Returns: VPC's ID<br>
Needs: VPC's friendly name, which is always "vpc-\<env>"<br>
Example:<br>
```{{aws:ec2:vpc/vpc-id,vpc-{{ENV}}}}```<br>
which is looked in 'proto3' as:<br>
```{{aws:ec2:vpc/vpc-id,vpc-proto3}}```<br>
returning:<br>
```vpc-21ac3315```<br>

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
aws:route53:private-hosted-zone-id,mydomain.
fully qualified private zone name, ending with "."
Private Zone's ID in Route53
mydomain-staging.
Z2ASVW53V915EN
aws:route53:public-hosted-zone-id,<zone_name>.
example:
aws:route53:public-hosted-zone-id,mydomain.
fully qualified public zone name, ending with "."
Public Zone's ID in Route53
mydomain-staging.
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
