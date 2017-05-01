## Stand-Up Sequence for an Environment

#### See also:
- Instance Initialization and environment-customization
- S3 bucket and Cloudfront fixture resource mappings (table is also embedded in Name Patterns and Paths)

### Stand-up sequence

| What | How to stand it up |
| ---- | ------------------ |

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
- Attach policies to the group AllUsers	
<code>ef-cf fixtures/templates/policy-allusers.json global.<ACCOUNT_ALIAS> --commit</code>
<code>ef-cf fixtures/templates/policy-2fausers.json global.<ACCOUNT_ALIAS> --commit</code>
- Attach policies to the other IAM Groups	
<code>ef-cf fixtures/templates/policy-some-group.json global.<ACCOUNT_ALIAS> --commit</code>
- Global s3 logging buckets<br>
<code>ef-cf fixtures/templates/s3-logs.json global.<ACCOUNT_ALIAS> --commit</code>
- Global s3 buckets<br>
<code>ef-cf fixtures/templates/s3-configs.json global.<ACCOUNT_ALIAS> --commit</code>
- Global Web Application Firewall (WAF) shared rules<br>
_e.g. to create a shareable rule with office CIDRs_<br>
<code>ef-cf fixtures/templates/waf-rules.json global.<ACCOUNT_ALIAS> --commit</code>
- SNS topics for each global account<br>
<code>ef-cf fixtures/templates/sns-topics.json global.<ACCOUNT_ALIAS> --commit</code>
- Elastic IPs<br>
_Each Elastic IP is designated for use by a specific service in a specific environment.
However, the set of Elastic IPs itself is owned by the account. We maintain the set of
Elastic IPs as a global fixture in each account, defined in a single template to (1)
keep the IPs centrally managed; (2) make it difficult to lose/accidentally rotate out
elegated IPs due to a code change - there's no way to reclaim an Elastic IP address if
you give one up accidentally._<br>
<code>ef-cf fixtures/templates/elasticip.json global.<ACCOUNT_ALIAS> --commit</code>
- Roles for the global environments (needed in cloudtrail-logs only)<br>
<code>ef-generate global.<ACCOUNT_ALIAS> --commit</code>
- CloudTrail alarms for every account<br>
<code>ef-cf fixtures/templates/cloudtrail-logs.json global.<ACCOUNT_ALIAS> --commit</code>


#### 3. Environment-specific fixtures (scope is per-applicable-environment)
##### proto0..protoN, staging, prod, internal, mgmt.<ACCOUNT_ALIAS>, ...
- CloudFront Origin Access Identities (OAI) (MANUAL)
Account
OAIs (named for their origins)
<ACCOUNT_ALIAS>	
static.cx-prod.com
theanimeawards.com
partner.vrv.co
<ACCOUNT_ALIAS>	static.cx-staging.com
static.cx-proto0.com ... static.cx-proto3.com
<ACCOUNT_ALIAS>	orgchart.cx-internal.com
Create one OAI per environment for each CloudFront distribution that needs it.
An OAI authenticates Cloudfront to S3.
Every OAI is named for the origin and environment that it represents (e.g. 'static.cx-prod.com')
CloudFormation does not support OAI management, so we create OAIs through the AWS GUI at:
https://console.aws.amazon.com/cloudfront/home?region=us-west-2#oai:
VPC	ef-cf fixtures/templates/vpc.json <env> --commit
Network within VPC
subnet(s)
internet gateway
route table connections
ef-cf fixtures/templates/network.json <env> --commit
VPN
requires additional setup: at instantiation the VPN creates a pre-shared key that must be manually entered into our VPN endpoint
To download a router configuration version of the configuration for a router in the data center, use the web GUI: VPC Dashboard → VPN Connections → select a VPN → Download Configuration (Vendor: Generic, Platform: Generic, Software: Vendor Agnostic)
ef-cf fixtures/templates/vpn.json <env> --commit
Roles and security groups for every <env>-<service>
ef-generate <env> --commit
Inline policies onto roles from /policy_templates directory
Customer-Managed Keys (CMKs) in KMS for every <service>
static fixture security groups
e.g. set the office ip addresses in the CIDR security group
ef-cf fixtures/templates/sg.json <env> --commit
Per-environment common S3 buckets	
ef-cf fixtures/templates/s3-logs.json <env> --commit
ef-cf fixtures/templates/s3-credentials.json <env> --commit
ef-cf fixtures/templates/s3-static.json <env> --commit
Per-environment service S3 buckets (s3-*), and buckets and queues together (s3-sqs-*) where bucket events create messages in the SQS queues	
ef-cf fixtures/templates/s3-aaweb.json prod --commit (prod only)
ef-cf fixtures/templates/s3-cms-imagestore.json <env> --commit
ef-cf fixtures/templates/s3-ecom-manga.json <env> --commit
ef-cf fixtures/templates/s3-orgchart.json internal --commit
ef-cf fixtures/templates/s3-partnerfeed.json prod --commit (prod only)
ef-cf fixtures/templates/s3-sqs-cms-ingest.json --commit
ef-cf fixtures/templates/s3-vod-ingest.json <env> --commit
ef-cf fixtures/templates/s3-vod-media.json <env> --commit
DNS hosted zones
DNS hosted zone glue records for delegated subdomains
MANUAL FOLLOWUP: Update domain NS records in whois if zones were created for the first time or nameservers changed
ef-cf fixtures/templates/hosted-zones.json <env> --commit

(warning) TBD (script coming)
CloudFront distributions with their WAFs
ef-cf fixtures/templates/cloudfront-aaweb.json prod --commit (prod only)
ef-cf fixtures/templates/cloudfront-api.json <env> --commit
ef-cf fixtures/templates/cloudfront-ecom.json <env> --commit
ef-cf fixtures/templates/cloudfront-partner.json prod --commit (prod only)
ef-cf fixtures/templates/cloudfront-portal.json <env> --commit
ef-cf fixtures/templates/cloudfront-secure.json prod --commit (prod only)
ef-cf fixtures/templates/cloudfront-static.json <env> --commit
ef-cf fixtures/templates/cloudfront-vod.json <env> --commit
ef-cf fixtures/templates/cloudfront-vod-cdnorigin.json <env> --commit
ef-cf fixtures/templates/cloudfront-web.json <env> --commit
ef-cf fixtures/templates/cloudfront-orgchart.json internal --commit
DNS records for public-facing endpoints
for flexibility in production, we manage the DNS records for public endpoints separately from the resources to which they refer. For example, during maintenance, we may need to point a name away from its usual resource.
ef-cf fixtures/templates/dns-nonprod-public-endpoints.json <env> --commit
ef-cf fixtures/templates/dns-prod-public-endpoints.json prod --commit
SNS topics for CloudWatch to publish alarms	
ef-cf fixtures/templates/sns-topics.json <env> --commit
Elasticsearch logging	ef-cf fixtures/templates/logs-elasticsearch.json <env> --commit
#### Management services (scope is mgmt environment only)
Lambdas that keep security groups updated with CloudFront IP addresses
ef-cf fixtures/templates/update-cfr-security-groups.json mgmt.<ACCOUNT_ALIAS> --commit

#### Application services (scope is per-environment); repeat for each service
individual services with their private resources
"...the ESS service stack...
... with its RDS, private Redis,
... service-specific S3 buckets
... lambda(s)
... and other service-specific resources"
ef-cf cloudformation/services/templates/<service_short_name>.json <env> --commit
CloudWatch Alarms for the service	TBD, using fixtures/templates/cloudwatch.json iterating over all services
Post-stand-up initialization for the service
e.g. initialize database with (what?). tbd (warning)

