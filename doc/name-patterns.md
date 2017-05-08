## Name Patterns and Paths

### General rules for all names

- Unless the pattern explicitly states otherwise, use lowercase characters a-z, digits 0-9, '-', and '_' only in names.
- '-' (hyphen) is a delimiter between fields of a compound name composed of many fields<br>
- Examples:
  - <code>prod-myservice1</code>
  - <code>staging-myservice2</code>
- Sometimes separator characters cause conflicts in names across AWS resources.
  - For example, RDS names contain "-" (<env>-<service>).
  - An RDS name could also contain "." if <service> is a sub-service (e.g. "myservice.cron").
  - However, RDS names are also used as DNS names, and therefore cannot contain a ".".
  - In this case, substitute "-" for the "." such that the first RDS for the "myservice.cron" service is named "\<env>-myservice-cron" rather than "\<env>-myservice.cron".
  - See also: Limitations on AWS IAM Entities and Objects<br>

### Service short names
- Every service and fixture has a short name that identifies it in name strings throughout the architecture in AWS, config files, and tools.
- Replace \<service\> in any name pattern with this short name.
- Short names are anchored in the Service Registry (/path/to/your/service_registry.json) which contains descriptive records for all services.
  - A service without an entry in the sevice registry cannot be stood up by ef-cf.
- Don't use or abbreviate the word "service" as part of a service's short name
- Examples:
  - full service name: Billing Service
  - shortname: billing

### Names for AWS Resources not explicitly defined here 
- Most names are formed as "\<env\>-\<service\>" such as "prod-myservice1" or "proto0-myservice2".
Most names are always used within a context that identifies the type of resource. So it is usually not necessary or useful to include a resource type in the name of the resource.
In a few cases, we do include resource information in a name. For example, we label security groups that connect dissimilar resources (for example, an ELB to its EC2 instances) so that we can see what's connecting to what. For security group names, we append the name of the resource ("ec2", "lambda", or "elb").
For resources that don't have naming conventions explicitly written out here, adopt the above pattern. 
Default to "<env>-<service>" whenever possible. Expand that to "<env>-<service>-<additional_identifier>" as needed.
Environment names
See also VRV Environments.
Environment names comprise a segment of resource names and paths to configuration and other environment-specific data. Generally the short-name of the environment is used
Env (literally <env> below)
Description
Note
prod
production environment
Exists in a separate AWS account from all other environments
staging
staging environment
Last stop before production. Configured very similarly to production.
proto<N>
prototype environment
Ephemeral stacks. Initially we support four, "proto0..proto3". At most we will support ten, 0..9.
global
not in any environment
special case for lambdas, s3 buckets, and not much else. These resources are accessible and in the service of assets in multiple environments (such as the common s3 ...-config and -dist buckets)
mgmt	management environment	This environment holds non-product support resources, including Jenkins and other tools that drive automation and operations. Some resources in the mgmt environment have access to resources in the product environments (Jenkins, for example) within the same account.
Security Group and Role Names
type (from ETP Service Registry)
Security Group name(s)
Role name
Stack name
aws_ec2
<env>-<service>-ec2
example:
prod-ess-ec2
<env>-<service>
<env>-<service>
http_service
ec2: <env>-<service>-ec2
elb: <env>-<service>-elb

example:
prod-ess-ec2
prod-ess-elb 
ec2: <env>-<service>
elb: N/A 
<env>-<service>
aws_lambda
<env>-<lambda_base_name>-lambda
example:
prod-i-do-something-lambda
prod-ess-i-do-something-lambda
<env>-<lambda_service_name>
(see Lambda names below) 
<env>-<lambda_service_name>
(see Lambda names below)  
aws_fixture
N/A
N/A
<env>-<service>
prod-network 
aws_security_group
<env>-<service>
example:
staging-cloudfront-ingress 
N/A
<env>-<service>
staging-cloudfront-ingress 
Policy names
inline policies
name should be descriptive of what the policy provides
use all lowercase; separate words with underscores
reminders
inline policies for services are created by ef-generate based on the service registry, using policy templates from the /policy_templates directory of the ellation_formation repo.
policies for service-owned resources created within a service's CloudFormation template are defined within the same template as the service
examples of policy filenames in the /policy_templates directory:
global_buckets_ro.json
instance_introspection.json
managed policies
We do not use managed policies except in the Codemobs account. Give policies meaningful, descriptive names.
EC2 Subnet, VPC, and VPN names
Pattern
aws_resource_name ::= [subnet|vpc|vpn]-<env>
Examples
subnet-staging
vpc-prod
EC2 Instance names
Every instance belongs to a Security Group that controls its network access, and an EC2 Role that controls its AWS resources access.
instance name == role name == security group name == <env>-<service>
We say both "the RDS service" (an AWS service) and "the CMS service" (our service)
Pattern
ec2_instance_name ::= security_group_name == role_name ::= <env>-<service>
<env> is the environment (prod, staging, proto<N>)
<service> is the short-name for the service, e.g. "cms"
Examples
prod-cms, staging-ess

EC2 Elastic Network Interface (ENI) names
We create ENIs to assign fixed IP addresses to special instances - for example, the "dnsproxy" host in each environment has a fixed internal IP address that it gets from an ENI created in advance and attached to it.
We use the "description" field of the ENI for a uniformly-formatted, unique string that identifies it for lookup by the AWS resolver
Pattern
eni_description ::= eni-<env>-<service>-<N>-<subnet_letter>
<env> is the environment (prod, staging, proto<N>)
<service> is the service name, if the ENI is assigned to a service.
If the ENI was created to hold an address for future use, but is not presently in use, use the string "unassigned" for <service>
<N> is just a sequential identifier for the ENI within the set, starting with 1
<subnet_letter> is "a" or "b" indicating the subnet the ENI is in
Examples
eni-proto3-dnsproxy-1a, eni-proto3-dnsproxy-1b
RDS DNS Names
Pattern for RDS instances owned by one service
rds_dns_name ::= rds-<env>-<service>[-<description>]
Optional <description> distinguishes DBs when more than one RDS belongs to a service
Pattern for RDS instances shared by multiple services with no clear owner
rds_dns_name ::= rds-<env>-<description>
<description> describes the database
Implementation and example
RDS instances come up with arbitrary hostnames
rds-dev-ess.cqz7jnavhp9u.us-west-2.rds.amazonaws.com
To make the RDS findable by apps at a constant name, we map a CNAME (following the patterns above) to the actual RDS name
rds-dev-ess.cx-<env>.com

RDS Replica Names
Production databases (production only) can have one read replica for offline reporting, and 1 to 4 read replicas for performance purposes for tables with heavy read traffic.
Cloudformation item
Production Replicas (in realtime path)
Reports only
Notes →	there could be up to 4 production read replicas, numbered 1-4	there is only ever one read replica for reports
Security Group Resource ID	RdsDbReplica1SecurityGroup	RdsDbReplicaReportSecurityGroup
Security Group Description	{{ENV}}-{{SERVICE}}.rds.replica-1	{{ENV}}-{{SERVICE}}.rds.replica-report
Replica Resource ID	RdsReplica1	RdsReplicaReport1
DbInstanceIdentifier	{{ENV}}-{{SERVICE}}-replica-1	{{ENV}}-{{SERVICE}}-replica-report
Private DNS Name	{{SERVICE}}.rds.replica-1.cx-{{ENV}}.com	{{SERVICE}}.rds.replica-report.cx-{{ENV}}.com
SQS Names
Queue
Pattern
queue_name ::= <env>-<service>-<contents-of-queue>
Example
in template: {{ENV}}-api-target-data-import 
rendered: staging-api-target-data-import 
Related dead letter queue
Every queue should have a "RedrivePolicy" that diverts unprocess-able objects to a dead-letter queue so they don't overwhelm queue or its consumers. The names of dead letter queues are always based on the names of the queues they back.
Pattern
deadletter_queue_name ::= <queue_name>-deadletter
Example
in template: {{ENV}}-api-target-data-import-deadletter 
rendered: staging-api-target-data-import-deadletter  
S3 Bucket Names and Key Paths
Foundations: Relevant S3 Guidance/Restrictions
S3 User Guide (at AWS)
See VRV System Security for S3 bucket replication and versioning guidance
S3 bucket names are globally unique; there is no way to reserve a namespace in S3
General rules for S3 buckets
Use lowercase characters only in bucket names, following the "Bucket names" patterns below
Use lowercase characters only in keys, unless there are many keys and the keys are managed by code (e.g. generated keys used in video services)
Because of the way they're implemented by AWS, S3 buckets exist outside the context of environments and accounts. 
We prefix all bucket names with "ellation-cx" to place them in a "namespace" but we can't prevent others from using it (unlikely by accident, possible if a malicious actor acquired an AWS account with the intent of interfering with us)
If a bucket name is not available because a non-Ellation account has a bucket with that name:
... well, first, we hope that a bucket prefixed with "ellation-cx" prefix will never collide with some other account's bucket
AWS doesn't offer a clean fix for this case
We would have to rename a service if a bucket name is unavailable to us, in order to maintain consistent name patterns (we have zero exceptions now)
Set "DeletionPolicy" of the bucket to "Retain" unless you have a good reason not to
In the CloudFormation template: "DeletionPolicy": "Retain",
This interferes with CloudFormation's "Delete Stack", but is preferable to losing bucket contents if a stack is erroneously deleted
To delete a bucket configured this way:
Delete the stack that defines the bucket. It will eventually stop with an error because the bucket is still there.
Manually delete the bucket via the S3 GUI or command line
Delete the stack again, telling it to ignore any not found resources
S3 buckets are usually fixtures created in a separate fixture template, not in a service template (there can be exceptions)
Define a bucket in its own fixture template when...
The bucket is "global" (it is a universally shared bucket connected to no specific service and available to all environments)
The bucket is not "global" but is an infrastructure bucket
configs, credentials, dist, logs, versions, ...
The bucket belongs to a service but the bucket contents should persist even if the service stack is deleted
This rule covers close to 100% of all remaining S3 use cases
By defining the bucket to its own template (and stack), we limit interactions with it, which in turn reduces the risk of damage or loss of the bucket due to unrelated cloudformation operations. A "stack update" happens every time we deploy a service. S3 buckets are rarely modified, and they're modified carefully when we do change them. Accordingly, they are much more like fixtures than services, which can come and go. This pattern also yields cleaner, shorter service templates centered on the service itself - servers, load balancers, and security groups.
The bucket isn't part of a conventional "service"
Example: partnerfeed bucket, which holds files we upload from jenkins, that are downloaded by partners such as Apple
The bucket is shared by more than one service
Examples: static, cms-imagestore 
When creating a bucket as a fixture, name its fixture template file...
"s3-<service>.json" if the template creates one or more S3 buckets and no SQS queues
"s3-sqs-<service>" if the template creates one or more S3 buckets along with one or more SQS queues that receive events from the bucket(s)

Exception: you may define the bucket within a service's template, rather than as a fixture, when...
The bucket can be created and destroyed along with the service
Example: a bucket that is only used for temporary storage by a single service could be handled this way
As of 3/2017, no buckets are created in this manner. All buckets are fixtures. This exception remains defined in case an appropriate use case should arise.
Table of infrastructure buckets and service buckets that are stood up as fixtures
Source: https://docs.google.com/a/ellation.com/spreadsheets/d/1anL81D68t27vI6jX0n3z4-uZXXv0Eh0M3wYcLtc8I2I/edit?usp=sharing
(also shows cloudfront distributions and their envs)

Bucket names
Every bucket name follows one of these patterns:
Service-owned bucket (used by one or more services, see more detailed example below):
pattern: ellation-cx-<env>-[service]-<content>
example: ellation-cx-prod-cms-ingest
Infrastructure bucket (core component of the ETP architecture)
pattern: ellation-cx-[<env>|global|global.<account>]-<infrastructure_bucket_suffix>
example: ellation-cx-global-configs
HTTP direct (serves content directly via HTTP, without CloudFront ahead of it
Per AWS requirements, must be named exactly as the FQDN that is CNAMEd to it
There's only one case of this pattern at present:
pattern: <contents>.vrv.co (production) or <contents>.cx-<env>.com (non-production)
example: partnerfeed.vrv.co (we did not create partnerfeed.cx-<env>.com as there was no need)
Bucket ownership and environment component of bucket name
System-wide buckets that hold content for all environments in all accounts
owned by account: ellation (the production account)
<env> string: "global"
example: ellation-cx-global-config
Environment-specific buckets
owned by account: whatever account owns the environment
<env> string: <env_full>, which appends ".account" for mgmt environments (and global envs temporarily)
example pattern: ellation-cx-<env_full>-credentials
example actual names: ellation-cx-staging-credentials, ellation-cx-mgmt.ellation-credentials
HTTP direct buckets follow the same ownership rules as environment-specific buckets; they're just named differently
example pattern: partnerfeed.<domain>
example actual name: partnerfeed.vrv.co, owned by the prod account (ellation)
example name the same bucket in staging: partnerfeed.cx-staging.com, owned by the non-prod account (ellationeng)
Infrastructure buckets
These names are reserved for infra and cannot be service names.
infrastructure_bucket_suffix
What's in the bucket
-configs
Application/service configuration data. Configuration buckets are shared; services' configuration files and corresponding file of parameters to localize a service to an environment, are found on a path within a config bucket.
Written by Jenkins when triggered by a commit to Github; read by the configuration script at instance initialization. 
-credentials
Encrypted credentials apps to use to sign on to RDS, SES, and other services.
Written by our credential-management tool; read by the configuration script at instance initialization. 
-dist
Build artifacts for all services.
Written by Jenkins, read by instances at startup to load application code.
-logs
 
S3 bucket activity logs for the above.
-static	Static content for any service
-versions	Version tracking by service, environment, asset/resource

S3 key-paths for service configuration
These objects are jointly managed by DevOps (who manage the tooling that places configs on instances) and by service developers (who decide what about their services to be configured). The use case for "configuration" data is service configuration and environment customization, loaded by services as they come up. Config objects are processed during init to build config files that are then used by the apps to start up.
Config data is stored the ellation_formation repo in the /configs directory.
Bucket
s3://ellation-cx-global-configs
Pattern
configuration_template_path ::= /<service>/templates/<filename.ext>
configuration_parameter_path ::= /<service>/parameters/<filename.ext>.parameters.json 
Examples
/cms-portal/templates/nginx.conf
/cms-portal/parameters/nginx.conf.parameters.json
S3 key-paths for Jenkins artifacts (built applications) in the global-dist bucket
Bucket and top path
s3://ellation-cx-global-dist/<service>
Full path pattern
artifact_path ::= /<service>/[app]/<artifact>
[app] would allow the possibility of > 1 build artifact per service – TBD
S3 key-paths for lambdas in the global-dist bucket
Bucket and top path
s3://ellation-cx-global-dist/lambdas
Pattern
artifact_path ::= /lambdas/[app]/<artifact>
[app] would allow the possibility of > 1 build artifact per service – TBD
S3 buckets and key paths for service-owned buckets
Bucket name in the CloudFormation template:
if the service has one bucket
  ellation-cx-{{ENV}}-{{SERVICE}}
if the service has more than one bucket
  ellation-cx-{{ENV}}-{{SERVICE}}-<content>
Examples:
  ellation-cx-staging-cms-ingest
  ellation-cx-prod-vod-media
  ellation-cx-proto3-vod-ingest 

Logging bucket and path
All logs are captured in the environment's shared "-logs" bucket, ellation-cx-<env>-logs
/{{SERVICE}}
or
/{{SERVICE}}-<content> 
Keys and paths within the bucket should be defined by the service owner in whatever manner is appropriate for the service's needs
Key path patterns should be documented in the service runbook as appropriate
If get or put rates will approach or exceed 100 RPS, see Request Rate and Performance Considerations in the AWS Developer Guide
S3 key paths for static content in the shared -static buckets
All services share the static buckets, "ellation-cx-<env>-static"
Every service has a top-level path that is the name of the service:
Pattern:
ellation-cx-<env>-static/<service>
Example:
in template: ellation-cx-<env>-static/{{SERVICE}}
rendered: ellation-cx-staging-static/vrvweb
Logging bucket is shared:
ellation-cx-<env>-static-logs/
Log path is "{{SERVICE}}/"
Keys and paths below <service>/ in the static bucket path are arranged entirely at the discretion of the service owner
Please document key path patterns in the service runbook, so that ops and others can understand the key structure if it becomes necessary to troubleshoot the bucket
If get or put rates will approach or exceed 100 RPS, see Request Rate and Performance Considerations in the AWS Developer Guide and talk to DevOps. A service-specific S3 bucket may be necessary for high-traffic buckets.
S3 Bucket LogFilePrefix
Every environment has a shared "-logs" bucket that all other S3 buckets write their logs to. Each bucket has its own path within the -logs bucket.
log_bucket_name ::= ellation-cx-<environment>-logs
example: ellation-cx-staging-logs
If a CloudFormation template creates only one S3 bucket and no SQS queues, the bucket's logging path is its service name, usually "s3-service>/"
In a Cloudformation template, the LogFilePrefix element of LoggingConfiguration of "AWS::S3::Bucket" is written this way:
{{SERVICE}}/
For S3 buckets created as fixtures (100% of buckets at this writing), this LogFilePrefix yields something like:
s3-partnerfeed/
If a Cloudformation template creates more than one S3 bucket, or the template creates both S3 buckets plus related SQS queues, then the bucket's logging prefix is derived from the bucket name, and {{SERVICE}}/ is not used to define the LogFilePrefix
To the get the LogFilePath for a bucket in a multi-bucket or bucket-and-SQS template:
Replace the prefix "ellation-cx-<env>-" in the bucket's name with "s3-".
Append a "/"
Example:
if the bucket name is: ellation-cx-{{ENV}}-cms-ingest-uploads
then the LogFilePrefix is: s3-cms-ingest-uploads/
Note: if bucket and template naming conventions have been followed, this pattern generates the same LogFilePrefix as {{SERVICE/}} if used in a single-bucket template.
S3 Key-paths for credentials
These objects, as well as secrets/credentials stored on them, are managed by DevOps and stored in a shared credential bucket
Use cases for credentials include database keys, GitHub read-only "deploy" tokens, and other secrets needed by services
Credentials must only be stored in "credentials" buckets (see name pattern above)
Pattern
credential_key_path ::= /<resource>/<type>[/<type_qualifier>]
<resource> is the common short name of any AWS resource, or of one of our services to which the object pertains. Valid values for <resource>:
cloudfront : the cloudfront service (most commonly used to provide a private key used for edge authentication
<service> : the shortname of any service (AWS or our own) that requires authentication
<database> : the common name of a database in RDS (TBD w/ devs)
<type> is the description of the actual object stored at this key. Valid values for <type>:
(warning) this may be condensed if (username,password) pairs are stored as JSON in one S3 object
rsa_private_key
rsa_public_key
smtp_username (e.g. to authenticate to SES)
smtp_password (e.g. to authenticate to SES)
password
username
<type_qualifier> distinguishes multiple distinct keys of the same "type" with unique purposes. 
For example, a database may have both read-only, and read+update username:password pairs.
If a type_qualifier is not needed, omit it.
<type_qualifier> values aren't defined at this time. Possible examples for anticipated use cases
readonly - a credential that grants read-only access to a database
update - a credential that grants update access to a database
Examples
/cloudfront/rsa_private_key : the current CloudFront private key
/user_database/username/readonly
/user_database/password/readonly
/user_database/username/update
Lambda and lambda-related names
 	
Pattern
How it's used
Example Name
lambda_base_name
lambda_base_name ::= <description>
What you'd call it if deployment details didn't matter...
This name the basis of all other names.
Valid characters: A-Z, a-z, 0-9, -
(restricfted by stack name) 
i-do-something
lambda_function_name
<env>-[<service>-]<lambda_base_name>
global-i-do-something
prod-i-do-something 
staging-ess-i-do-something 
lambda_artifact_name
lambda_artifact_name ::= <lambda_base_name>.py
Single-file Lambda with no dependencies, as stored in the repo and copied by Jenkins to S3.
i-do-something.py
lambda_artifact_name ::= <lambda_base_name>.zip
Packaged lambda with dependencies, as built and stored directly in S3.
For multi-file lambdas and lambdas that are packed and shipped with
dependencies, deployed into S3.
Note: this is the way forward for all lambdas.
i-do-something.zip
 
CloudFormation names
Stack name
Pattern: stack_name ::= <env>-<fixture_or_service_name>
Examples for fixtures: prod-s3, proto1-network, prod-i-do-something
Examples for services: prod-cx_api, proto2-vod
Template filename
Pattern: template_filename ::= <fixture_or_service_name>.json
Examples: network.json, cx_api.json
Parameter-file filename
Pattern: parameter_filename ::= <fixture_or_service_name>.parameters.<env>.json
Examples: network.parameters.proto0.json, s3.parameters.staging.json
References inside CloudFormation templates
CamelCase
Examples: Vpc, SubnetA, SubnetB, Dns, EssCron
AMI names
AMI's are generated from our Packer template inside of Jenkins. There are two Jenkins jobs that will produce AMI's.
<SERVICE>-ami : This Jenkins job contains the Chef integration pieces necessary to start and bring up the service.
Example: Jenkins job ess-ami
<SERVICE>-build: This Jenkins job will take the AMI that was built from step 1 and integrate it with the application code that has been compiled and built in this step.
Example: Jenkins job ess-build
The final AMI produced will be of this following pattern:
Pattern: ami_name ::= <SERVICE>[.<SUBSERVICE>]-release
Example: ess-release, ess.cassandra-release
