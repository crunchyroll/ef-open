
# Service registry
The service registry is a human- and machine-readable list of services, checked into version control.

It is intended for use by automation, and as the "source of truth" for all services.

There is one Service Registry entry for every CloudFormation template that we maintain in one of these directories of the infrastructure repo:
cloudformation/fixtures/templates (parameters in cloudformation/fixtures/parameters)
cloudformation/services/templates (parameters in cloudformation/services/parameters)
Service registry entries are arranged into groups. Presently we have three groups:
fixtures – fixtures are always present in ETP. A fixture is "an element of the infrastructure that is present in every applicable environment, whether or not the environment has services running in it at the time." Fixtures include foundational infrastructure from VPCs at the lowest level through CloudFront at the highest. Fixtures also include certain application components that are either shared between applications (to avoid an ordering dependency), that take a long time to create and carry nominal cost when not in use, and/or that we want to persist even when the application stack is deleted.
In short: fixtures are resources that are always present in even applicable environment.
Fixtures may have strong interdependencies and may have to be stood up in a specific sequence. We have documented the sequence at ETP Stand-Up Sequence. In a future version of the Service Registry and tooling, the sequence will be captured in the Service Registry itself.
These application components are created as fixtures in separate templates, not as part of a service template, so that they are always available, and persist even if the related application stack is deleted.
Cloudformation distributions
S3 buckets
See Software-Defined Architecture coding standards for more information about fixtures.
platform_services – platform services include all supporting services for an environment that are NOT part of an actual end-user or application-side services. Platform services include Jenkins and Jenkins slaves, the DNS proxy (under construction), Cloudfront security group lambdas, cingest, and logging.
application services – application services are all the services that make up the VRV application service tree: myservice1, cms, vrvweb, and so on.
internal services – application services specific to internal company operations.
Service registry location
The service registry is a single json file in the private company or project infrastructure repo at GitHub.
The Service Registry is also read from a local copy of the infrastructure registry by tools that needs it.
The file's name and location are:
<code>GitHub:$MY_REPO/service_registry.json</code>
At present service_registry.json is only used directly from a local copy of the repo, and is not distributed to S3.
Accordingly, before running tools that rely on the service registry, 'git pull' should first be run to update the local copy before using the tool. All our tools that depend on the service registry will generally do a 'git pull' at startup and confirm the branch is 'master' at startup.
Service registry use by tools
ef-generate reads the service registry to create security groups and roles with friendly names, and attach policy templates from /policies to roles.
ef-cf reads the service registry to validate command line args (such as the requested environment) when creating or updating stacks
ef-version (under construction) will read the service registry to set versions of the application services in an environment when the "all" command is used
Service Registry structure
Not all fields are required for all 'types'. See table below.  This structure is evolving and may change.
{
  "fixtures|application_services|platform_services|internal_services": {
    "service": {
	  "type": "aws_cloudtrail | aws_ec2 | aws_fixture | aws_lambda | aws_role | aws_security_group| http_service",
	  "description": "longer description",
	  "runbook_url": "URL of our Confluence runbook about this thing (even aws fixtures)",
	  "team_email": "email_of_service_owner@mydomain.com",
	  "environments": ["global.<account_alias>","prod","staging","proto","mgmt.<account_alias>"],
	  "jira_project": "project",
	  "chef_role": "role",
	  "policies": ["<policy1>",...],
	  "assume_role_policy": "<policy>"
	},
  	...
  }
}
Conditionally-required fields
If a field is present for a type, it is required.
All services have these fields, whose names are mostly self-explanatory.
service – the shortname of the service
type
description
runbook_url
team_email
environments 
Conditional fields based on 'type'
type	Description	Additional required fields
aws_cloudtrail	A cloudtrail	
aws_ec2	
An ec2 instance of ours that is not an http microservice.
Security group name: <env>-<service>-ec2
jira_project
chef_role
service_port
policies 
aws_fixture	
A miscellaneous AWS service created alone (a fixture) in a specific environment - not a compute resource, and not otherwise defined as a more-specific "type" here. (e.g. global 'network' or 's3') 
No security groups are created
N/A
aws_lambda with env "global"	
A global lambda not belonging to any service, outside all environments.
(e.g. the introspector lambda)
Security group name: <env>-<lambda_name>-lambda
jira_project
policies
aws_lambda with env not "global"	
A lambda not belonging to any service, but created in a specific environment.
(e.g. the CloudFormation whitelist updater lambda, deployed into prod) 
Security group name: <env>-<lambda_name>-lambda
jira_project
policies 
aws_role	A role. When ef-generate runs, it will simply make a role, nothing else. Requires assume_role_policy which provides the name of the policy file (in /policy_templates) that defines what's allowed to assume this role.	assume_role_policy
aws_security_group	
A security group. When ef-generate runs, it will simply make a security group, nothing else.
Security group name: <env>-<name> (where "name" is the label on the service registry entry
N/A
http_service	
A service of ours, built with packer/chef, running in EC2, and created in a specific environment with all its private dependencies via CloudFormation.
(e.g. vod-nginx) 
It is assume that http_service resources consist of EC2 instance(s) behind an ELB. Two security groups are created for http_service resources:
Security group name for the ELB: <env>-<service>-elb
Security group name for the EC2 instances: <env>-<service>-ec2
jira_project
chef_role
service_port 
policies 
 1 See ETP Name Patterns and Paths 
Service Registry example with data
{
  "introspector": {
    "type": "aws_lambda",
    "description": "Introspector lambda to assist CloudFormation references",
    "runbook_url": "TBD",
    "jira_project": "CXOPS",
    "team_email": "ops-team@mycompany.com",
    "environments": ["global.myprodacount", "global.mynonprodaccount"],
    "policies": ["global-buckets-ro", "instance-introspection"]
  },
  "vpc": {
    "type": "aws_fixture",
    "description": "Network config - VPC and 1 or 2 subnets",
    "runbook_url": "TBD",
    "team_email": "ops-team@mycompany.com",
    "environments": ["prod", "staging", "proto", "global.myprodaccount"]
  },
  "myservice1": {
    "type": "http_service",
    "description": "Service 1",
    "runbook_url": "https://path/to/myservice1_runbook",
    "jira_project": "MYS1",
    "chef_role": "myservice1",
    "team_email": "service1team@mycompany.com",
    "environments": ["prod", "staging", "proto"],
    "policies": ["global-buckets-ro", "instance-introspection"]
  },
  "cloudfront-ingrmyservice1": {
    "type": "aws_security_group",
    "description": "Security group only - holds CloudFront IPs for ingrmyservice1 to service ELBs",
    "team_email": "ops-team@mycompany.com",
    "environments": ["prod", "staging", "proto"]
  }
},
...
 
}
Role and Security Group assignment by resource type
Resource
Type
Env
create Security Group
create Role
lambda	aws_lambda	prod, staging, proto<N>	<env>-<name>-lambda	<env>-<name>
global lambda	aws_lambda	global	N/A	
<env>-<name>
ec2 instance	aws_ec2	prod, staging, proto<N>	<env>-<service>-ec2	<env>-<name>
http service (ec2 + elb)	http_service	prod, staging, proto<N>	always two, named:
<env>-<service>-elb
<env>-<service>-ec2 	<env>-<name>
security group	aws_security_group	prod, staging, proto<N>	<service>	N/A
other AWS resource	aws_fixture	prod, staging, proto<N>, global	N/A	N/A
Subservices
Here is an example of a service + its subservice defined in the service registry.
What's going on below?
The main service "myservice1":
type is "http_service" = it's comprised of EC2 instances behind an ELB (and maybe other stuff)
"environments" indicates it can be stood up in prod, staging, proto0, proto1, proto2, proto3
running ef-generate will create these fixtures:
security group '<env>-myservice1-elb' and '<env>-myservice1-ec2' (two, due to type="http_service")
role named '<env>-myservice1'
instance profile named '<env>-myservice1' with the role attached to it
policies from /policy_templates and named in the "policies" section attached to the role
instance definitions in CloudFormation should use the instance profile "<env>-myservice1" which also connects them to the role "<env>-myservice1" and the policies attached to it
to build the service's stack in AWS, use ef-cf with its CloudFormation template, whose name must be:
 cloudformation/services/templates/myservice1.json
when it is starting up, the instance will load config templates and parameters from the S3 path "myservice1.gearman-worker" in the -configs bucket
The sub-service "myservice1.gearman-worker":
type is "aws_ec2" = it contains one (or a set of) freestanding EC2 instance(s)
"environments" indicates it can be stood up in prod, staging, proto0, proto1, proto2, proto3 (should ultimately inherit from its parent, "myservice1", and not list its own envs separately)
running ef-generate will create these fixtures:
security group '<env>-myservice1.gearman-worker' (due to type="aws_ec2")
role named '<env>-myservice1.gearman-worker'
instance profile named '<env>-myservice1.gearman-worker' with the role attached to it
policies from /policy_templates and named in the "policies" section attached to the role
instance definitions in CloudFormation should use the instance profile "<env>-myservice1.gearman-worker" which also connects them to the role "<env>-myservice1.gearman-worker" and the policies attached to it
the subservice cannot be deployed separately - use ef-cf with the main service (myservice1) tio to build the service's stack in AWS, use ef-cf with its CloudFormation template, whose name must be:
 cloudformation/services/templates/myservice1.json
when it is starting up, the instance will load config templates and parameters from the S3 path "myservice1.gearman-worker" in the -configs bucket
"myservice1": {
    "type": "http_service",
    "description": "My service 1",
    "runbook_url": "https://path/to/myservice1_runbook",
    "jira_project": "myservice1",
    "chef_role": "myservice1",
    "team_email": "myservice1-team@mycompany.com",
    "environments": ["prod", "staging", "proto"],
    "policies": ["global_buckets_ro", "instance_introspection"]
  },
  "myservice1.gearman-worker": {
    "type": "aws_ec2",
    "description": "My service 1",
    "runbook_url": "https://path/to/myservice1_runbook",
    "jira_project": "myservice1",
    "chef_role": "myservice1",
    "team_email": "myservice1-team@mycompany.com",
    "environments": ["prod", "staging", "proto"],
    "policies": ["global_buckets_ro", "instance_introspection"]
  }
}
 
