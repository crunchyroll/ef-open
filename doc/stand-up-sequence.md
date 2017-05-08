## Global and Environment Stand-Up Sequence

#### See also:
- Instance Initialization and environment-customization
- S3 bucket and Cloudfront fixture resource mappings (table is also embedded in Name Patterns and Paths)

### Stand-up sequence
#### 1a. Always-present IAM Groups (create once per account)
_When adding a user to the account via IAM, make the user a member of this group.
The AllUsers group allows the minimum necessary self-management (password and MFA self-help)
plus read access to the production and non-production AWS tooling (architecture, instance views, and metrics only, not data or access to instances)_

- Using the CLI for AWS IAM, create a group named "AllUsers" in each account<br>
<code>$ aws iam create-group --group-name AllUsers --profile <ACCOUNT_ALIAS></code>

#### 1b. Service/Environment/Application-specific IAM Groups (create once per account)
- Using the CLI for AWS IAM, create other groups<br>
<code>$ aws iam create-group --group-name SomeGroup --profile <ACCOUNT_ALIAS></code>


#### 2. Global fixtures (scope is per-account)
- Attach policies to the group AllUsers<br>
<code>ef-cf fixtures/templates/policy-allusers.json global.<ACCOUNT_ALIAS> --commit</code><br>
<code>ef-cf fixtures/templates/policy-2fausers.json global.<ACCOUNT_ALIAS> --commit</code><br>
- Attach policies to the other IAM Groups<br>
<code>ef-cf fixtures/templates/policy-some-group.json global.<ACCOUNT_ALIAS> --commit</code><br>
- Global s3 logging buckets<br>
<code>ef-cf fixtures/templates/s3-logs.json global.<ACCOUNT_ALIAS> --commit</code><br>
- Global s3 buckets<br>
<code>ef-cf fixtures/templates/s3-configs.json global.<ACCOUNT_ALIAS> --commit</code><br>
- Global Web Application Firewall (WAF) shared rules<br>
_e.g. to create a shareable rule with office CIDRs_<br>
<code>ef-cf fixtures/templates/waf-rules.json global.<ACCOUNT_ALIAS> --commit</code><br>
- SNS topics for each global account<br>
<code>ef-cf fixtures/templates/sns-topics.json global.<ACCOUNT_ALIAS> --commit</code><br>
- Elastic IPs<br>
_Each Elastic IP is designated for use by a specific service in a specific environment.
However, the set of Elastic IPs itself is owned by the account. We maintain the set of
Elastic IPs as a global fixture in each account, defined in a single template to (1)
keep the IPs centrally managed; (2) make it difficult to lose/accidentally rotate out
elegated IPs due to a code change - there's no way to reclaim an Elastic IP address if
you give one up accidentally._<br>
<code>ef-cf fixtures/templates/elasticip.json global.<ACCOUNT_ALIAS> --commit</code><br>
- Roles for the global environments (needed in cloudtrail-logs only)<br>
<code>ef-generate global.<ACCOUNT_ALIAS> --commit</code><br>
- CloudTrail alarms for every account<br>
<code>ef-cf fixtures/templates/cloudtrail-logs.json global.<ACCOUNT_ALIAS> --commit</code><br>


#### 3. Environment-specific fixtures (scope is per-applicable-environment)
##### envs are: proto0..protoN, staging, prod, internal, mgmt.<ACCOUNT_ALIAS>, ...
- CloudFront Origin Access Identities (OAI) (MANUAL)<br>
Account OAIs (named for their origins, examples:<br>
||ACCOUNT || OAIs (named for their origins)||
| ------- | ------------------------------- |
| myaccount | static.myaccount-prod.com|
| myaccount2 | www.myaccount-prod.com |

_Create one OAI per environment for each CloudFront distribution that needs it._<br>
_An OAI authenticates Cloudfront to S3._<br>
_Every OAI is named for the origin and environment that it represents (e.g. 'static.myaccount.com')_<br>
_CloudFormation does not support OAI management, so we create OAIs through the AWS GUI at:_<br>
https://console.aws.amazon.com/cloudfront/home?region=us-west-2#oai:
- VPC<br>
<code>ef-cf fixtures/templates/vpc.json \<env\> --commit</code>
- Network within VPC: subnet(s), Internet gateway, route table connections<br>
<code>ef-cf fixtures/templates/network.json \<env\> --commit</code>
- VPN<br>
_requires additional setup: at instantiation the VPN creates a pre-shared key that must be manually entered into the VPN endpoint_<br>
_To download a router configuration version of the configuration for a router in the data center, use the web GUI: VPC Dashboard → VPN Connections → select a VPN → Download Configuration. Then select vendor and software version, or use Vendor: Generic, Platform: Generic, Software: Vendor Agnostic for human-readable details._<br>
<code>ef-cf fixtures/templates/vpn.json \<env\> --commit</code>
- Roles and security groups for every \<env\>-\<service\><br>
Inline policies onto roles from /policy_templates directory<br>
Customer-Managed Keys (CMKs) in KMS for every service<br>
<code>ef-generate \<env\> --commit</code>
- Static fixture security groups<br>
_e.g. set the office ip addresses in the CIDR security group_<br>
<code>ef-cf fixtures/templates/sg.json \<env\> --commit</code><br>
- Per-environment common S3 buckets<br>
<code>ef-cf fixtures/templates/s3-logs.json \<env\> --commit</code><br>
<code>ef-cf fixtures/templates/s3-credentials.json \<env\> --commit</code><br>
<code>ef-cf fixtures/templates/s3-static.json \<env\> --commit</code><br>
- Per-environment service-owned S3 buckets (s3-\*)<br>
S3 buckets and queues together (s3-sqs-*) where bucket events create messages in the SQS queues<br>
<code>ef-cf fixtures/templates/s3-MYSERVICE1.json prod --commit (prod only)</code><br>
<code>ef-cf fixtures/templates/s3-MYSERVICE2-BUCKET1.json \<env\> --commit</code><br>
<code>ef-cf fixtures/templates/s3-MYSERVICE2-BUCKET2.json \<env\> --commit</code><br>
<code>ef-cf fixtures/templates/s3-sqs-MYSERVICE3.json \<env\> --commit</code><br>
- DNS hosted zones<br>
_DNS hosted zone glue records for delegated subdomains_<br>
_MANUAL FOLLOWUP: Update domain NS records in whois if zones were created for the first time or nameservers changed (needs a script)_<br>
<code>ef-cf fixtures/templates/hosted-zones.json \<env\> --commit</code>
- CloudFront distributions with their WAFs<br>
<code>ef-cf fixtures/templates/cloudfront-MYSERVICE1.json prod --commit (prod only)</code><br>
<code>ef-cf fixtures/templates/cloudfront-MYSERVICE2.json prod --commit (prod only)</code><br>
<code>ef-cf fixtures/templates/cloudfront-static.json \<env\> --commit</code><br>
- DNS records for public-facing endpoints<br>
_for flexibility in production, we manage the DNS records for public endpoints separately from the resources to which they refer. For example, during maintenance, we may need to point a name away from its usual resource._<br>
<code>ef-cf fixtures/templates/dns-nonprod-public-endpoints.json \<env\> --commit</code><br>
<code>ef-cf fixtures/templates/dns-prod-public-endpoints.json prod --commit</code><br>
- SNS topics for CloudWatch to publish alarms<br>
<code>ef-cf fixtures/templates/sns-topics.json \<env\> --commit</code><br>
- Elasticsearch logging<br>
<code>ef-cf fixtures/templates/logs-elasticsearch.json \<env\> --commit</code><br>

#### Management services (scope is mgmt environment only)
- Lambdas that keep security groups updated with CloudFront IP addresses<br>
<code>ef-cf fixtures/templates/update-cfr-security-groups.json mgmt.<ACCOUNT_ALIAS> --commit</code><br>

#### Application services (scope is per-environment); repeat for each service
- individual services with their private resources<br>
_eg: "...the MYSERVICE stack... with its private RDS, private Redis, internal DNS entries, ELBs, ..._<br>
<code>ef-cf cloudformation/services/templates/<service_short_name>.json \<env\> --commit</code><br>
- CloudWatch or other Alarms for the service (TBD)<br>
_TBD, possibly using fixtures/templates/cloudwatch.json + service registry to iterate over all services_<br>
- Post-stand-up initialization for the service<br>
_e.g. initialize database with (what?). tbd
