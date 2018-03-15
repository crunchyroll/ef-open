## What does the ellation_formation ef-cf tool do?

The main difference in CF templating is the availability of {{SYMBOLS}} to fill in values from the AWS environment.

We switch from this non-human-auditable, manually-looked-up form (for example, to refer to a security group):

`"GroupId": "sg-803a8e34"`

... to a human-auditable, machine-looked-up form:

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
returns:<br>
```arn:aws:acm:us-west-2:0123456789012:certificate/abcdef01-0123-abcd-0123-01234567890a```

#### {{aws:cloudfront:domain-name,\<cname>}}
Returns: Domain name of the CloudFront distribution that hosts a given CNAME<br>
Needs: Any domain name that's a CNAME on the desired CLoudFront distribution<br>
Example:<br>
```{{aws:cloudfront:domain-name,static.mydomain-{{ENV}}.com}}```<br>
which is looked up in env "proto3" as:<br>
```{{aws:cloudfront:domain-name,static.mydomain-proto3.com}}```<br>
returns:<br>
```d6mwasxvryve1.cloudfront.net```

#### {{aws:cloudfront:origin-access-identity/oai-canonical-user-id,\<oai_fqdn>}}
Returns: Amazon S3 Canonical User ID associated with an Origin Access Identity (identified by the comment on the OAI, which for us is always a FQDN) FQDN<br>
Needs: FQDN that the Origin Access Identity (OAI) is associated with. When we create an OAI, we add a comment that identifies the domain that it's for. The comment is what's used for the lookup.<br>
Note: In our process, the "Comment" on the OAI is literally the FQDN, e.g.: "static.mydomain-proto3.com"<br>
Example:<br>
```{{aws:cloudfront:origin-access-identity/oai-canonical-user-id,static.mydomain-{{ENV}}.com}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:cloudfront:origin-access-identity/oai-canonical-user-id,static.mydomain-proto3.com```<br>
returns:<br>
```c1dabc158c3cca7db15d511cbe6661319ae8111d56b113ab751411171a51e16e9baa7d1d4e4c8a1b9363c4111bdad4a7```

#### {{aws:cloudfront:origin-access-identity/oai-id,\<oai_fqdn>}}
Returns: ID of the Origin Access Identity associated with the FQDN (identified by the comment on the OAI, which for us is always a FQDN) FQDN<br>
Needs: FQDN that the Origin Access Identity (OAI) is associated with. When we create an OAI, we add a comment that identifies the domain that it's for. The comment is what's used for the lookup.<br>
Note: In our process, the "Comment" on the OAI is literally the FQDN, e.g.: "static.mydomain-proto3.com"<br>
Example:<br>
```{{aws:cloudfront:origin-access-identity/oai-id,static.mydomain-{{ENV}}.com}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:cloudfront:origin-access-identity/oai-id,static.mydomain-proto3.com```<br>
returns:<br>
```A2Q53T2TMX231E```

#### {{aws:ec2:elasticip/elasticip-id,\<elasticip_resourceid>}}
Returns: Allocation ID of the Elastic IP whose resource ID is <elasticip_resourceid><br>
Needs: Resource ID of the Elastic IP (and thus in the CF stack)<br>
Note: in our process, the Resource ID is set in the elasticip.json fixture template, and is composed as: "ElasticIP\<ENV>\<SERVICE>"<br>
Example:<br>
```{{aws:ec2:elasticip/elasticip-id,ElasticIpMgmtMyService1}}```<br>
returns:<br>
```eipalloc-b351cab5```<br>

#### {{aws:ec2:elasticip/elasticip-ipaddress,\<elasticip_resourceid>}}
Returns: Public IP address of the Elastic IP whose resource ID is \<elasticip_resourceid><br>
Needs: Resource ID of the Elastic IP (and thus in the CF stack)<br>
Note: in our process, the Resource ID is set in the elasticip.json fixture template, and is composed as: "ElasticIP\<ENV>\<SERVICE>"<br>
Example:<br>
```{{aws:ec2:elasticip/elasticip-ipaddress,ElasticIpMgmtMyService1}}```<br>
returns:<br>
```35.161.255.167```<br>

#### {{aws:ec2:eni/eni-id,\<eni_description>}}
Returns: ID of the Elastic Network Interface having the <eni_description><br>
Needs: "Description" field of the Elastic Network Interface to be looked up.
Note: In our process, the Description field of an ENI is composed as:<br>
```eni-{{ENV}}-{{SERVICE}}-<N><subnet_letter>```<br>
pattern:<br>
```{{aws:ec2:eni/eni-id,eni-{{ENV}}-{{SERVICE}}-<N><subnet_letter>}}```<br>
Example - interface '1' in subnet 'a' in env 'proto3' for the 'myservice' service is looked up as:<br>
```{{aws:ec2:eni/eni-id,eni-proto3-myservice-1a}}```<br>
returns:<br>
```eni-31ca3f1a```

#### {{aws:ec2:network/network-acl-id,\<network_acl_friendly_name>}}
Returns: Network ACL ID<br>
Needs: Network ACL's friendly name<br>
Example:<br>
```{{aws:ec2:network/network-acl-id,acl-{{ENV}}-<subnet_name>}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:ec2:network/network-acl-id,acl-proto3-subnetA}}```<br>
returns:<br>
```acl-be2d211a```<br>

#### {{aws:ec2:route-table/main-route-table-id,\<vpc_name>}}
Returns: Route table ID<br>
Needs: Friendly name of the VPC containing the main route table, always "vpc-\<env>"<br>
Example:<br>
```{{aws:ec2:route-table/main-route-table-id,vpc-{{ENV}}}}```<br>
which is looked up in 'prod' as:<br>
```{{aws:ec2:route-table/main-route-table-id,vpc-prod}}```<br>
returns:<br>
```rtb-3f820be9a```<br>

#### {{aws:ec2:route-table/tagged-route-table-id,\<route_table_name>}}
Returns: Route table ID<br>
Needs: the tagged route table name, should be unique<br>
Example:<br>
```{{aws:ec2:route-table/tagged-route-table-id,{{ENV}}-dmz}}```<br>
returns:<br>
```rtb-3f820be9a```<br>

#### {{aws:ec2:security-group/security-group-id,\<sg_friendly_name>}}
Returns: Security group ID<br>
Needs: Security group's friendly name<br>
Example:<br>
```{{aws:ec2:security-group/security-group-id,{{ENV}}-myservice}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:ec2:security-group/security-group-id,proto3-myservice}}```<br>
returns:<br>
```sg-78fe34a6```<br>

#### {{aws:ec2:subnet/subnet-cidr,\<subnet_friendly_name>}}
Returns: subnet CIDR<br>
Needs: Subnet's friendly name, which is always "subnet-\<env>-\<az>"<br>
Example:<br>
```{{aws:ec2:subnet/subnet-cidr,subnet-{{ENV}}-a}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:ec2:subnet/subnet-cidr,subnet-proto3-a}}```<br>
returns:<br>
```0.0.0.0/0```<br>

#### {{aws:ec2:subnet/subnet-id,\<subnet_friendly_name>}}
Returns: subnet ID<br>
Needs: Subnet's friendly name, which is always "subnet-\<env>-\<az>"<br>
Example:<br>
```{{aws:ec2:subnet/subnet-id,subnet-{{ENV}}-a}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:ec2:subnet/subnet-id,subnet-proto3-a}}```<br>
returns:<br>
```subnet-be2d211a```<br>

#### {{aws:ec2:vpc/cidrblock,\<vpc_friendly_name>}}
Returns: VPC's CIDR block<br>
Needs: VPC's friendly name, which is always "vpc-\<env>"<br>
Example:<br>
```{{aws:ec2:vpc/cidrblock,<vpc_name>}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:ec2:vpc/cidrblock,vpc-proto3}}```<br>
returns:<br>
```10.8.64.0/18```<br>

#### {{aws:ec2:vpc/vpc-id,\<vpc_friendly_name>}}
Returns: VPC's ID<br>
Needs: VPC's friendly name, which is always "vpc-\<env>"<br>
Example:<br>
```{{aws:ec2:vpc/vpc-id,vpc-{{ENV}}}}```<br>
which is looked in 'proto3' as:<br>
```{{aws:ec2:vpc/vpc-id,vpc-proto3}}```<br>
returns:<br>
```vpc-21ac3315```<br>

#### {{aws:ec2:vpc/availabilityzones,\<vpc_friendly_name>}}
Returns: Comma-separated list of availability zones that contain subnets within the VPC, with internal double-quotes (external double-quotes come from the template)<br>
Needs: Friendly name of the VPC serving the target environment, which is always "vpc-\<env>"<br>
Example (use exactly like this in a JSON template, including [ ] and the dual quotes):<br>
```"AvailabilityZones": [ "{{aws:ec2:vpc/availabilityzones,vpc-{{ENV}}}}" ]```<br>
which is looked up in 'prod' as:<br>
```"AvailabilityZones": [ "{{aws:ec2:vpc/availabilityzones,vpc-prod}}" ]```<br>
returns:<br>
```"us-west-2a","us-west-2b"```<br>
which resolves to this if the above example was followed exactly:<br>
```"AvailabilityZones": [ "us-west-2a","us-west-2b" ]```

#### {{aws:ec2:vpc/subnets,\<vpc_friendly_name>}}
Returns: Comma-separated list of all subnet IDs within the VPC, with internal double-quotes (external double-quotes come from the template)
Needs: Friendly name of the vpc serving the target environment, which is always "vpc-\<env>"
Example (use exactly like this in a JSON template, including [ ] and the dual quotes):<br>
```"Subnets": [ "{{aws:ec2:vpc/subnets,vpc-{{ENV}}}}" ]```<br>
which is looked up in 'staging' as:<br>
```"Subnets": [ "{{aws:ec2:vpc/subnets,vpc-staging}}" ]```<br>
which resolves to this if the above example was followed exactly:<br>
```"Subnets": [ "subnet-aac314be","subnet-aac351fa" ]```<br>

#### {{aws:kms:decrypt,\<kms_encrypted_data>}}
Returns: Decrypted copy of kms-encrypted string<br>
Needs: Base64 encoded string encrypted using the unique service/environment kms key generated by ef-password<br>
Example 1 (Cloudformation Template):<br>
```"MasterUserPassword": { "Ref": "DbPassParam" }```<br>
This will refer to the value found in the environment paramters JSON:
```
{
    "ParameterKey": "DbUserParam",
    "ParameterValue": "{{aws:kms:decrypt,AQICAHgtk0pYU9G1rCODigWoZcXcZW5fKBOTBQD/8s4qq1DTTgHbE/sR4gQQ4oBuQ0MmBtLtAAAAYzBhBgkqhkiG9w0BBwagVDBSAgEAME0GCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMci3LiBQwEQfSdV0vAgEQgCDVbxzz/fcS2BZyiuG1T/RtudZ+4ii4tYWkdq35datbGg==}}"
}
```
Example 2 (Config Template):<br>
configs/myservice/templates/sample_config.ini<br>
```
[database]
db_user=Admin
db_password={{encrypted_db_password}}
```
configs/myservice/parameters/sample_config.ini.parameters.json<br>
```
...
"params": {
    "staging": {
      "encrypted_db_password": "{{aws:kms:decrypt,AQICAHgtk0pYU9G1rCODigWoZcXcZW5fKBOTBQD/8s4qq1DTTgHbE/sR4gQQ4oBuQ0MmBtLtAAAAYzBhBgkqhkiG9w0BBwagVDBSAgEAME0GCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMci3LiBQwEQfSdV0vAgEQgCDVbxzz/fcS2BZyiuG1T/RtudZ+4ii4tYWkdq35datbGg==}}"
    }
}
```




#### {{aws:route53:private-hosted-zone-id,\<zone_name>.}}
Returns: Private Hosted Zone's ID in Route53<br>
Needs: fully qualified private zone name, ending with "."<br>
Example:<br>
```{{aws:route53:private-hosted-zone-id,mydomain-{{ENV}}}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:route53:private-hosted-zone-id,mydomain-proto3}}```<br>
returns:<br>
```Z20EFA41X32AM```

#### {{aws:route53:public-hosted-zone-id,\<zone_name>.}}
Returns: Public Hosted Zone's ID in Route53<br>
Needs: fully qualified public zone name, ending with "."<br>
Example:<br>
```{{aws:route53:public-hosted-zone-id,mydomain-{{ENV}}}}```<br>
which is looked up in 'proto3' as:<br>
```{{aws:route53:public-hosted-zone-id,mydomain-proto3}}```<br>
returns:<br>
```Z20EFA87A26E8```

#### {{aws:waf:rule-id,\<waf_rule_name>}}
Returns: WAF rule's ID<br>
Needs: friendly name of the WAF rule<br>
Example:<br>
```{{aws:waf:rule-id,global-officeCidr}}```<br>
returns:<br>
```0af1232a-a60a-433a-cd3a-20d62ada238a```<br>

#### {{aws:waf:web-acl-id,\<web_acl_name>}}
Returns: WAF rule's ID<br>
Needs: friendly name of the WAF rule<br>
Example:<br>
```{{aws:waf:web-acl-id,{{ENV}}-StaticAcl}}```<br>
which is looked up in 'prod' as:<br>
```{{aws:waf:web-acl-id,prod-StaticAcl}}```<br>
returns:<br>
```0af2012e-b24e-55ba-ec2b-132d2e51268a```<br>


### EF Config (local config) lookup symbols

#### {{efconfig:accountaliasofenv,\<env>}}
Returns: A value from the EFConfig constants that control ef tools<br>
Needs: The ID of the configuration value to be looked up<br>
Example:<br>
```{{efconfig:accountaliasofenv,{{ENV}}}}```<br>
which is looked up in 'staging' as:<br>
```{{efconfig:accountaliasofenv,staging}}```<br>
returns:<br>
```myaccountalias```<br>

### Version lookup symbols

#### {{version:ami-id,\<env>/\<service_name>}}
Returns: The ID of the designated AMI for the current environment<br>
Needs: service name, from which the AMI name will be composed<br>
Note: AMIs must be named "\<service_name>-release"<br>
Example:<br>
```{{version:ami-id,{{ENV}}/myservice}}```<br>
which is looked up in 'prod' as:<br>
```{{version:ami-id,prod/myservice}}```<br>
returns:<br>
... the AMI ID for the service 'myservice' in the environment 'prod'<br>
```ami-abcd0123```<br>


### Examples of the various forms of "ENV" in templates and how they resolve

| Environment	| Account | ENV Resolves to	| ENV_SHORT resolves to	| ENV_FULL resolves to |
| ----------- | ------- | --------------- | --------------------- | -------------------- |
| prod | N/A | prod | prod | prod |
| staging	| N/A	| staging	| staging	| staging |
| proto<1..N> | N/A	| protoN | proto | protoN |
| global | myaccountalias | global | global | global.myaccountalias |
| global | myaccountalias2 | global | global | global.myaccountalias2 |
| internal | myintaccountalias | internal | internal | internal.myintaccountalias |
| mgmt | myaccountalias | mgmt | mgmt | mgmt.myaccountalias |
| mgmt | myaccountalias2 | mgmt | mgmt | mgmt.myaccountalias2 |
