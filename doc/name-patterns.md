## Name Patterns and Paths

### General rules for all names

- Unless the pattern explicitly states otherwise, use lowercase characters a-z, digits 0-9, '-', and '_' only in names.
- '-' (hyphen) is a delimiter between fields of a compound name composed of many fields&lt;br>
- Examples:
  - &lt;code>prod-myservice1&lt;/code>
  - &lt;code>staging-myservice2&lt;/code>
- Sometimes separator characters cause conflicts in names across AWS resources.
  - For example, RDS names contain "-" (&lt;env>-&lt;service>).
  - An RDS name could also contain "." if &lt;service> is a sub-service (e.g. "myservice.cron").
  - However, RDS names are also used as DNS names, and therefore cannot contain a ".".
  - In this case, substitute "-" for the "." such that the first RDS for the "myservice.cron" service is named "\&lt;env>-myservice-cron" rather than "\&lt;env>-myservice.cron".
  - See also: Limitations on AWS IAM Entities and Objects&lt;br>

### Service short names
Every service and fixture has a short name that identifies it in name strings throughout the architecture in AWS, config files, and tools.
- Replace \&lt;service\> in any name pattern with this short name.
- Short names are anchored in the Service Registry (/service_registry.json in your infra repo) which contains descriptive records for all services.
  - A service without an entry in the service registry cannot be stood up or operated on by ef-open
- Don't use or abbreviate the word "service" as part of a service's short name
- Examples:
  - full service name: Billing Service
  - shortname: billing

### Names for AWS Resources not explicitly defined here
Most names are formed as "&lt;env>-&lt;service>" such as "prod-myservice1" or "proto0-myservice2".
Because names are predominantly used within contexts that explicitly or implicitly identifies the type of resource named,
do not include the resource type in the resource's name.
- In a few cases, we do include resource information in a name
  - We label security groups that connect dissimilar resources (for example, an ELB to its EC2 instances) so that we can see what's connecting to what.
    - Append the type of the resource ("-ec2", "-lambda", or "-elb").
- For resources that don't have naming conventions explicitly written out here, adopt the above pattern.
- Default to "&lt;env>-&lt;service>" whenever possible. Expand that to "&lt;env>-&lt;service>-&lt;additional_identifier>" as needed.

### Environment names
Environment names comprise a segment of resource names and paths to configuration and other environment-specific data.
Generally the short-name of the environment is used.

- See also: EF-Open Environments

| Env (literally &lt;ENV\> below) | Description | Note |
| --- | --- | --- |
| prod | production environment | Exists in a separate AWS account from all other environments |
| staging | staging environment | Last stop before production. Configured very similarly to production (production w/o scale) |
| proto&lt;N> | prototype environment | Ephemeral stacks. Initially we support four, "proto0..proto3". At most we can support ten, 0..9 |
| global | not in any environment | special case for lambdas, s3 buckets, and not much else. Global resources are accessible by, and in the service of, assets in all environments (such as the common s3 ...-config and -dist buckets) |
| mgmt | management environment	| This environment holds non-product support resources, including Jenkins and other tools that drive automation and operations. Some resources in the mgmt environment have access to resources in the product environments (Jenkins, for example) within the same account. |

### Security Group and Role Names based on Service Registry 'type'

| type (from Service Registry) | Security Group name(s) | Role name | Stack name|
| --- | --- | --- | --- |
| aws_ec2 | &lt;env>-&lt;service>-ec2<br>example:<br>prod-myservice-ec2 | &lt;env>-&lt;service> | &lt;env>-&lt;service> |
| http_service | ec2: &lt;env>-&lt;service>-ec2<br>elb: &lt;env>-&lt;service>-elb<br>examples:<br>prod-myservice-ec2<br>prod-myservice-elb | ec2: &lt;env>-&lt;service><br>elb: N/A | &lt;env>-&lt;service> |
| aws_lambda | &lt;env>-&lt;lambda_base_name>-lambda<br>examples:<br>prod-myservice-i-do-something-lambda | &lt;env>-&lt;lambda_service_name><br>(see Lambda names below) | &lt;env>-&lt;lambda_service_name><br>(see Lambda names below) |
| aws_fixture | N/A | N/A | &lt;env>-&lt;service><br>example:<br>prod-network |
| aws_security_group | &lt;env>-&lt;service><br>example:<br>staging-cloudfront-ingress | N/A | &lt;env>-&lt;service><br>example:<br>staging-cloudfront-ingress |

### Policy names

#### Inline policies
Inline policies for services are created by ef-generate based on the service registry, using policy templates from the /policy_templates directory of the ellation_formation repo.

Policies for service-owned resources created within a service's CloudFormation template are defined within the same template as the service.

- Name should be descriptive of what the policy provides
- use all lowercase characters; separate words with underscores
- examples of policy filenames in the /policy_templates directory:
  - global_buckets_ro.json
  - instance_introspection.json

#### Managed policies
We do not use managed policies except in the sandbox account. Give policies meaningful, descriptive names.

### EC2 Subnet, VPC, and VPN names
#### Pattern for Subnet, VPC, and VPN names
<code>aws_resource_name ::= [subnet|vpc|vpn]-&lt;env></code><br>
#### Examples of Subnet, VPC, and VPN names
<code>subnet-staging, vpc-prod</code>

### EC2 Instance names
Every instance belongs to a Security Group that controls its network access, and an EC2 Role that controls its AWS resources access.

<code>instance name == role name == security group name == &lt;env>-&lt;service></code><br>

We say both "the RDS service" (an AWS service) and "the payment service" (our service)
#### Pattern for EC2 Instance names
<code>ec2_instance_name ::= security_group_name == role_name ::= &lt;env>-&lt;service></code>
- &lt;env> is the environment (prod, staging, proto&lt;N>)
- &lt;service> is the short-name for the service, e.g. "cms"

#### Examples of EC2 Instance names
prod-cms, staging-ess

### EC2 Elastic Network Interface (ENI) names
We create ENIs to assign fixed IP addresses to special instances. For example, a DNS proxy host in each environment would have a fixed internal IP address that it gets from an ENI created in advance and attached to it.

We set the "description" field of the ENI to a uniformly-formatted, unique string that identifies it for lookup by the AWS resolver

#### Pattern for EC2 Elastic Network Interface (ENI) names
<code>eni_description ::= eni-&lt;env>-&lt;service>-&lt;N>-&lt;subnet_letter></code><br>
- &lt;env> is the environment (prod, staging, proto&lt;N>)
- &lt;service> is the service name, if the ENI is assigned to a service
- If the ENI was created to hold an address for future use, but is not presently in use, use the string "unassigned" for &lt;service>
- &lt;N> is a sequential identifier for the ENI within the set, starting with 1
- &lt;subnet_letter> is a single character ("a","b", ...) indicating the subnet the ENI is in

#### Examples of EC2 Elastic Network Interface (ENI) names
<code>eni-proto3-dnsproxy-1a, eni-proto3-dnsproxy-1b</code>

### RDS DNS Names
#### Pattern for RDS instance names for instances owned by one service
<code>rds_dns_name ::= rds-&lt;env>-&lt;service>[-&lt;description>]</code><br>

0 Optional &lt;description> distinguishes DBs when more than one RDS belongs to a service

#### Pattern for RDS instance names for instances shared by multiple services with no dominant owner
<code>rds_dns_name ::= rds-&lt;env>-&lt;description></code><br>
- &lt;description> describes the database

#### Implementation and examples of RDS DNS Names
- RDS instances come up with arbitrary hostnames, e.g.:<br>
<code>rds-dev-ess.cqz7jnavhp9u.us-west-2.rds.amazonaws.com</code>
- To make the RDS findable by apps, we map a constant CNAME (following the patterns above) to the actual RDS name:<br>
<code>rds-dev-ess.cx-&lt;env>.com</code>

### RDS Replica Names
Production databases (prod environment only) may have one read replica for offline reporting, and 1 to 4 additional read replicas for performance purposes to support tables with heavy read traffic.

| Cloudformation item | Production Replicas | Reports only |
| --- | --- | --- |
| _Notes →_ |	_There could be up to 4 production read replicas, numbered 1-4_ | _There is only ever one read replica for reports_ |
| Security Group Resource label | RdsDbReplica1SecurityGroup	| RdsDbReplicaReportSecurityGroup |
| Security Group Description in CF Template | {{ENV}}-{{SERVICE}}.rds.replica-1 | {{ENV}}-{{SERVICE}}.rds.replica-report |
| Replica Resource label | RdsReplica1 | RdsReplicaReport1 |
| DbInstanceIdentifier | {{ENV}}-{{SERVICE}}-replica-1 | {{ENV}}-{{SERVICE}}-replica-report |
| Private DNS Name | {{SERVICE}}.rds.replica-1.cx-{{ENV}}.com | {{SERVICE}}.rds.replica-report.cx-{{ENV}}.com |

### SQS Names
#### Queue Name Pattern
<code>queue_name ::= &lt;env>-&lt;service>-&lt;contents-of-queue></code>
#### Queue Name Example
in template: <code>{{ENV}}-myservice-target-data-import</code><br>
resolved: <code>staging-myservice-target-data-import</code><br>

#### Related Dead Letter Queue Name Pattern
Every queue should have a "RedrivePolicy" that diverts unprocessable objects to a dead-letter queue so they don't overwhelm queue or consumers. The names of dead letter queues are always based on the names of the queues they back.

<code>deadletter_queue_name ::= &lt;queue_name>-deadletter</code>

#### Deadletter Queue Example
in template: <code>{{ENV}}-api-target-data-import-deadletter</code><br>
rendered: <code>staging-api-target-data-import-deadletter</code><br>

### S3 Bucket Names, Key Paths and Other Patterns for S3

#### Foundations: Relevant S3 Guidance/Restrictions
See also:
- S3 User Guide (at AWS)
- ETP System Security for S3 bucket replication and versioning guidance

AWS has implemented S3 buckets in a truly global way (across all of AWS). There is no namespacing, and a bucket name can only exist ones in all of AWS, regardless of the owning account. To implement pattern-based names, we must define a way to "namespace" all our buckets that strongly assures (there can be no absolute guarantee) that a given pattern-based name will be available when needed.

#### Namespacing S3 bucket names

- TL;DR
  - Every bucket name shares a prefix that we hope is sufficient to namespace away from everyone else's buckets.
  - The usual pattern is:<br>
  <code>S3PREFIX ::= &lt;company>-&lt;prefix></code><br>


- Prefix every bucket name with a unique, constant identifier.
  - pattern: <code>"&lt;companyname>-&lt;project>-"</code>
  - example: <code>mycompany-myproject-env-service-[optional_description]</code>
  -  There is no way to prevent others from taking a name that follows this pattern, either by accident or by malice. Use your best judgement as this is a global decision that will be very hard to change later.
  - If a third party's bucket name does collide, the only solution is to rename the service, or use the optional description field to distinguish the bucket name.
- Use lowercase characters only in bucket names, following the "Bucket names" patterns below
- Use lowercase characters only in object keys, unless there are many keys and the keys are managed by code (e.g. keys generated by application code)

#### S3 bucket deletion policies
- Set "DeletionPolicy" of the bucket to "Retain" unless you have a good reason not to (there is rarely a good reason not to retain a bucket)
  - In the CloudFormation template: <code>"DeletionPolicy": "Retain",</code>
- This interferes with a clean exit from CloudFormation's "Delete Stack", but is preferable to losing bucket contents if a stack is erroneously deleted.
- Most S3 buckets are fixtures, meaning they are created in advance of, and independently from, the service's stack. So, once created, S3 buckets are rarely if ever deleted, regardless of what goes on with the related service itself.
- To delete a bucket configured with "DeletionPolicy: Retain":
  - Delete the CloudFormation stack that defines the bucket.
  - CloudFormation will eventually stop with an error because the bucket is still there.
  - Manually delete the bucket via the S3 GUI or command line.
  - Delete the stack again, telling it to ignore any not found resources.

#### Define most S3 buckets in their own fixture templates, not in service templates.
By defining an S3 bucket to its own template (and thus, CloudFormation stack), we limit interactions with it. This reduces the risk of damage or loss of the bucket due to unrelated CloudFormation on a service. A "stack update" happens every time we deploy a service. By contrast, S3 buckets are rarely modified, and they're modified carefully when we do change them. Accordingly, they are much more like fixtures, which are long-lived and rarely vary, than they are like services, which may come and go.

This pattern also yields cleaner, shorter service templates centered on the service itself - servers, load balancers, and security groups.

In practice, all, or nearly all, S3 buckets are created as fixtures in separate templates, as described here.

##### When is a bucket a fixture?
- The bucket is "global" (it is a universally shared bucket connected to no specific service and available to all environments)
- The bucket is not "global" but is an infrastructure bucket
  - examples: configs, credentials, dist, logs, versions, ...
- The bucket belongs to a service but the bucket contents should persist even if the service stack is deleted. This rule covers close to 100% of all S3 use cases not covered by the previous two items.
- The bucket isn't part of a conventional "service"
  - Example: a special-purpose bucket used as a distribution point for WWW delivery to business partners or app downloads, or to back a website.
- The bucket is shared by more than one service
  - Example: a static assets bucket, which service highly-cacheable objects directly through CloudFront

##### How to name the template file for an S3 "fixture" bucket
When creating a bucket as a fixture, name its fixture template file...<br>
- <code>"s3-&lt;service>.json"</code> if the template creates one or more S3 buckets and no SQS queues
- <code>"s3-sqs-&lt;service>.json"</code> if the template creates one or more S3 buckets along with one or more SQS queues that receive events from the bucket(s). This is a common idiom. The buckets and SQS queues must be created together because of their interdependencies.

#### Exception: when it's OK to define a bucket in a service template
It's OK to define a bucket within a service's template, rather than as a fixture, when...
- The bucket can be created and destroyed along with the service
  - Example: a bucket that is only used for temporary storage by a single service
- This use case is rare in practice. This exception is defined in case an appropriate use case appears.

#### Table of infrastructure buckets and service buckets that are stood up as fixtures
<code>S3PREFIX ::= &lt;company>-&lt;prefix></code>

| Template name | Resource belongs<br>to env → | proto0,1,2,3 | staging | prod | mgmt.&lt;NONPROD_ALIAS> | mgmt.&lt;PROD_ALIAS> | global.&lt;PROD_ALIAS> | global.&lt;NONPROD_ALIAS> |
| --- | --- |:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Logging** |
| s3-logs.json | &lt;S3PREFIX&gt;-&lt;ENV_FULL>-logs | X | X | X | X | X | X | X |
| **System-wide buckets (all accounts/envs use them)** |
| s3-configs.json | &lt;S3PREFIX&gt;-global-configs | | | | | | X | |
| s3-dist.json | &lt;S3PREFIX&gt;-global-dist | | | | | | X | |
| s3-versions.json | &lt;S3PREFIX&gt;-global-versions | | | | | | X | |
| **Per-environment buckets (envs w/ compute resources only)** |
| s3-credentials.json | &lt;S3PREFIX&gt;-&lt;ENV_FULL>-credentials | X | X | X | X | X | | |
| **Application environments** |
| s3-myservice1.json | &lt;S3PREFIX&gt;-&lt;ENV>-myservice1 | X | X | X | | |	| |
| s3-mywebsite.json | website.mydomain.com | | | X | | | | |
| s3-static.json | &lt;S3PREFIX&gt;-&lt;ENV>-static | X | X | X | | |	| | |


#### Specific pattern: Service-owned bucket (used by one or more services)
pattern: <code>&lt;S3PREFIX>-&lt;env>-&lt;service>-[content]</code><br>
example: <code>mycompany-myproject-prod-myservice-images</code>

#### Infrastructure bucket (core component of the ETP architecture)
pattern: <code>&lt;S3PREFIX>-[&lt;env>|global|global.&lt;account>]-&lt;infrastructure_bucket_suffix></code>
example: <code>mycompany-myproject-global-configs</code>

#### HTTP direct (serves content directly via HTTP, without CloudFront ahead of it
Per AWS requirements, the bucket be named exactly as the FQDN that is CNAMEd to it.

pattern: <code>&lt;contents>.mydomain.com or &lt;contents>-mynonprodprefix-&lt;env>.com</code>
example: <code>media-downloads.mydomain.com</code> (which perhaps only has a prod version since it's a distribution point, not a service)

### Bucket ownership and environment component of bucket name
#### System-wide buckets that hold content for all environments in all accounts
- Owned by: production account
- &lt;env> is: "global"
- example: mycompany-myproject-global-config

#### Environment-specific buckets
- owned by: whatever account owns the environment
- &lt;env> is: &lt;env_full>, which appends ".&lt;account_alias>" for mgmt environments
- example pattern: <code>&lt;S3PREFIX&gt;-&lt;env_full>-credentials</code><br>
- example actual names:<br>
<code>mycompany-myproject-staging-credentials</code><br> <code>mycompany-myproject-mgmt.ellation-credentials</code>

#### HTTP direct buckets follow the same ownership rules as environment-specific buckets; they're just named differently
- example actual name: <code>media-downloads.&lt;mydomain.com></code>
  - owned by the prod account
- example actual name, same bucket, in staging: <code>media-downloads.&lt;mynonprodprefix>-staging.com</code>
  - owned by the non-prod account

### Infrastructure buckets
These names are reserved for infra and cannot be service names.

| Infrastructure_bucket_suffix | What's in the bucket |
|:--- |:--- |
| -configs | Application/service configuration data. Configuration buckets are shared; services' configuration files and corresponding file of parameters to localize a service to an environment, are found on a path within a config bucket.<br>Written by Jenkins when triggered by a commit to Github; read by the configuration script at instance initialization. |
| -credentials | Encrypted credentials apps to use to sign on to RDS, SES, and other services.<br>Written by our credential-management tool; read by the configuration script at instance initialization. |
| -dist | Build artifacts for all services.<br>Written by Jenkins, read by instances at startup to load application code. |
| -logs | S3 bucket activity logs for the above. |
| -static | Static content for any service |
| -versions | Version tracking by service, environment, asset/resource |

### S3 key-paths for service configuration
These objects are jointly managed by DevOps (who manage the tooling that places configs on instances) and by service developers (who decide what about their services to be configured).

The use case for "configuration" data is service configuration and environment customization, loaded by services as they come up. Config objects are processed during init to build config files that are then used by the apps to start up.

Config data is stored the Infrastructure repo in the /configs directory.

#### Service configuration bucket
s3://&lt;S3PREFIX&gt;-global-configs

##### Service configuration key path pattern
<code>configuration_template_path ::= /&lt;service>/templates/&lt;filename.ext></code><br>
<code>configuration_parameter_path ::= /&lt;service>/parameters/&lt;filename.ext>.parameters.json</code>

##### Service configuration key path example
<code>/myservice1/templates/nginx.conf</code><br>
<code>/myservice1/parameters/nginx.conf.parameters.json</code>

#### S3 key-paths for Jenkins artifacts (built applications) in the global-dist bucket
##### Bucket and top path
- <code>s3://&lt;S3PREFIX&gt;-global-dist/&lt;service></code>
##### Full path pattern
- <code>artifact_path ::= /&lt;service>/[app]/&lt;artifact></code>
  - [app] allows for > 1 build artifact per service

#### S3 key-paths for lambdas in the global-dist bucket
##### Bucket and top path
- <code>s3://&lt;S3PREFIX&gt;-global-dist/lambdas</code>
##### Full path pattern
- <code>artifact_path ::= /lambdas/[app]/&lt;artifact></code>
  - [app] allows for > 1 build artifact per service

#### S3 buckets and key paths for service-owned buckets
##### Bucket name in the CloudFormation template
- if the service has one bucket<br><code>&lt;S3PREFIX&gt;-{{ENV}}-{{SERVICE}}</code>
- if the service has more than one bucket<br><code>&lt;S3PREFIX&gt;-{{ENV}}-{{SERVICE}}-&lt;content></code>

##### Examples:
- <code>mycompany-myproject-myservice1-photos<br>mycompany-myproject-prod-myservice2</code>

##### Logging bucket and path for service-owned buckets
All logs are captured in the environment's shared "-logs" bucket, mycompany-myproject-&lt;env>-logs.
The path is:
- <code>/{{SERVICE}}</code>
or
- <code>/{{SERVICE}}-&lt;content></code>

- Keys and paths within the bucket should be defined by the service owner in whatever manner is appropriate for the service's needs
- Key path patterns should be documented in the service runbook as appropriate
- If get or put rates will approach or exceed 100 RPS, see Request Rate and Performance Considerations in the AWS Developer Guide

#### S3 key paths for static content in the shared -static buckets
All services share the static buckets: <code>&lt;S3PREFIX&gt;-&lt;env>-static</code>

Every service has a top-level path that is the name of the service.
- Pattern: <code>&lt;S3PREFIX&gt;-&lt;env>-static/&lt;service></code>
- Example:<br>
in template: <code>mycompany-myproject-{{ENV}}-static/{{SERVICE}}</code><br>
fully resolved in staging: <code>mycompany-myproject-staging-static/myservice</code>

The logging bucket for static content is also shared:
- <code>&lt;S3PREFIX&gt;-&lt;env>-static-logs/</code>
- The log path inside the static bucket is per-service: <code>"{{SERVICE}}/"</code>

#### S3 Bucket LogFilePrefix for environment-specific S3 buckets
Every environment has a shared "-logs" bucket that all other S3 buckets in that environment write their logs to. Each bucket has its own path within the -logs bucket.

- Pattern: <code>log_bucket_name ::= &lt;S3PREFIX&gt;-&lt;environment>-logs</code>
- Example: <code>mycompany-myproject-staging-logs</code>

If a CloudFormation template creates only one S3 bucket and no SQS queues, the bucket's logging path is its service name, usually "<code>s3-&lt;service>/</code>"

- How it's written in a CloudFormation template:
  - <code>{{SERVICE}}/</code>
- How it resolves for an S3 bucket created as a fixture (100% of buckets at this writing):
  - <code>s3-myservice1/</code>

If a Cloudformation template creates more than one S3 bucket, or the template creates both S3 buckets plus related SQS queues, then the bucket's logging prefix is derived from the bucket name, and {{SERVICE}}/ is not used to define the LogFilePrefix

- To the get the LogFilePath for a bucket in a multi-bucket or bucket-and-SQS template:
  - Replace the prefix "<code>mycompany-myproject-&lt;env>-</code> in the bucket's name with <code>s3-</code>
  - Append a "/"
  - Example:
    - Given a bucket name <code>mycompany-myproject-{{ENV}}-myservice-images</code>
    - LogFilePrefix is: <code>s3-myservice-images/</code>

_Note: if bucket and template naming conventions have been followed, this pattern generates the same LogFilePrefix as {{SERVICE/}} if used in a single-bucket template._

### S3 Key-paths for credentials
- Credential objects are stored in environment-specific credential buckets
- Use cases for credentials include database keys, GitHub read-only "deploy" tokens, and other secrets needed by services.
- Credentials must only be stored in "credentials" buckets.

#### Pattern for credential key-paths
<code>credential_key_path ::= /&lt;resource|service>/&lt;type>[/&lt;type_qualifier>]</code>
- <code>&lt;resource></code> is the common short name of any AWS resource, or the shortname of a service
- Valid values for &lt;resource>:
  - <code>cloudfront</code> : the cloudfront service (most commonly used to provide a private key used for edge authentication
  - <code>&lt;service></code> : the shortname of any service (AWS or our own) that requires authentication
  - <code>&lt;database> : the common name of a database in RDS (TBD w/ devs)
- <code>&lt;type></code> is the description of the actual object stored at this key. Valid values for <code>&lt;type>:</code>
  - <code>rsa_private_key</code>
  - <code>rsa_public_key</code>
  - <code>password</code>
  - <code>username</code>
- <code>&lt;type_qualifier></code> distinguishes multiple distinct keys of the same "type" with unique purposes. For example, a database may have both read-only, and read+update username:password pairs.
If a type_qualifier is not needed, omit it.

  - <code>&lt;type_qualifier></code> values aren't defined here but should be used consistently within a service, and preferably, across all services.

- Examples:<br>
<code>/cloudfront/rsa_private_key : the current CloudFront private key</code><br>
<code>/user_database/username/readonly</code><br>
<code>/user_database/password/readonly</code><br>
<code>/user_database/username/update</code><br>


### Lambda and lambda-related names

Lambdas are services, so the lambda's name in the infrastructure is the same as any plain service name:<br>
- pattern: <code>&lt;ENV&gt;-&lt;SERVICE&gt;
- in a CloudFormation template: <code>{{ENV}}-{{SERVICE}}</code>

Lambdas as deployed from source or ZIP files ("build artifacts" in the vernacular):
- pattern for a single file: <code>&lt;SERVICE&gt;.py</code>
  - example: <code>myservice3.py</code>


- pattern for a zipped multi-file build artifact: <code>&lt;SERVICE&gt;.py</code>
  - example: <code>myservice3.zip</code>


### CloudFormation names
#### Cloudformation stack name
- Pattern: <code>stack_name ::= &lt;env>-&lt;fixture_or_service_name></code>
- Examples for fixtures:
  - <code>prod-s3, proto1-network</code>
- Examples for services:
  - <code>prod-myservice1, proto3-myservice2</code>
- Template filename:
  - Pattern: <code>template_filename ::= &lt;fixture_or_service_name>.json</code>
  - Examples: <code>network.json, cx_api.json</code>
- Parameter-file filename:
  - Pattern: <code>parameter_filename ::= &lt;fixture_or_service_name>.parameters.&lt;env>.json</code>
  - Examples: <code>network.parameters.proto0.json, s3.parameters.staging.json</code>
- References inside CloudFormation templates:
  - CamelCase
  - Examples: <code>Vpc, SubnetA, SubnetB, Dns, EssCron</code>

### AMI names:
  - Pattern: <code>ami_name ::= &lt;SERVICE>[.&lt;SUBSERVICE>]-release</code>
  - Example: <code>myservice1-release, myservice2.mysubservice2A-release</code>
