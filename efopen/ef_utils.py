"""
provides simple utility functions used in many scripts

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
import base64
import json
from os import access, X_OK
from os.path import isfile, exists
import re
from socket import gethostname
import subprocess
import sys
import urllib2

import boto3
from botocore.exceptions import ClientError

from ef_config import EFConfig

__HTTP_DEFAULT_TIMEOUT_SEC = 5
__METADATA_PREFIX = "http://169.254.169.254/latest/meta-data/"
__VIRT_WHAT = "/sbin/virt-what"
__VIRT_WHAT_VIRTUALBOX_WITH_KVM = ["virtualbox", "kvm"]

# Matches CIDRs (loosely, TBH)
CIDR_REGEX = r"^(([1-2][0-9]{2}|[0-9]{0,2})\.){3}([1-2][0-9]{2}|[0-9]{0,2})\/([1-3][0-9]|[0-9])$"

# Cache for AWS clients. Keeps all the clients under (region, profile) keys.
client_cache = {}


def fail(message, exception_data=None):
  """
  Print a failure message and exit nonzero
  """
  print(message, file=sys.stderr)
  if exception_data:
    print(repr(exception_data))
  sys.exit(1)

def http_get_metadata(metadata_path, timeout=__HTTP_DEFAULT_TIMEOUT_SEC):
  """
  Fetch AWS metadata from http://169.254.169.254/latest/meta-data/<metadata_path>
  ARGS:
    metadata_path - the optional path and required key to the EC2 metadata (e.g. "instance-id")
  RETURN:
    response content on success
  RAISE:
    URLError if there was a problem reading metadata
  """
  metadata_path = __METADATA_PREFIX + metadata_path
  try:
    response = urllib2.urlopen(metadata_path, None, timeout)
    if response.getcode() != 200:
      raise IOError("Non-200 response " + str(response.getcode()) + " reading " + metadata_path)
    return response.read()
  except urllib2.URLError as error:
    raise IOError("URLError in http_get_metadata: " + repr(error))

def is_in_virtualbox():
  """
  Is the current environment a virtualbox instance?
  Returns a boolean
  Raises IOError if the necessary tooling isn't available
  """
  if not isfile(__VIRT_WHAT) or not access(__VIRT_WHAT, X_OK):
    raise IOError("virt-what not available")
  try:
    return subprocess.check_output(["sudo", "-n", __VIRT_WHAT]).split('\n')[0:2] == __VIRT_WHAT_VIRTUALBOX_WITH_KVM
  except subprocess.CalledProcessError as e:
    raise IOError("virt-what failed execution with {}".format(e))

def whereami():
  """
  Determine if this is an ec2 instance or "running locally"
  Returns:
    "ec2" - this is an ec2 instance
    "virtualbox-kvm" - kernel VM (virtualbox with vagrant)
    "local" - running locally and not in a known VM
    "unknown" - I have no idea where I am
  """
  # If the metadata endpoint responds, this is an EC2 instance
  # If it doesn't, we can safely say this isn't EC2 and try the other options
  try:
    response = http_get_metadata("instance-id", 1)
    if response[:2] == "i-":
      return "ec2"
  except:
    pass

  # Virtualbox?
  try:
    if is_in_virtualbox():
      return "virtualbox-kvm"
  except:
    pass

  # Outside virtualbox/vagrant but not in aws; hostname is "<name>.local"
  hostname = gethostname()
  if re.findall(r"\.local$", hostname):
    return "local"

  # we have no idea where we are
  return "unknown"

def http_get_instance_env():
  """
  Returns: just the env this ec2 instance is in. Doesn't require API access like get_instance_aws_context does
  Example return value: "staging"
  """
  try:
    info = json.loads(http_get_metadata('iam/info'))
  except Exception as error:
    raise IOError("Error looking up metadata:iam/info: " + repr(error))
  return info["InstanceProfileArn"].split(":")[5].split("/")[1].split("-",1)[0]

def http_get_instance_role():
  """
  Returns: just the role this ec2 instance is in. Doesn't require API access like get_instance_aws_context does
  Example return: "vrvweb"
  """
  try:
    info = json.loads(http_get_metadata('iam/info'))
  except Exception as error:
    raise IOError("Error looking up metadata:iam/info: " + repr(error))
  return info["InstanceProfileArn"].split(":")[5].split("/")[1].split("-",1)[1]

def get_instance_aws_context(ec2_client):
  """
  Returns: a dictionary of aws context
    dictionary will contain these entries:
    region, instance_id, account, role, env, env_short, service
  Raises: IOError if couldn't read metadata or lookup attempt failed
  """
  result = {}
  try:
    result["region"] = http_get_metadata("placement/availability-zone/")
    result["region"] = result["region"][:-1]
    result["instance_id"] = http_get_metadata('instance-id')
  except IOError as error:
    raise IOError("Error looking up metadata:availability-zone or instance-id: " + repr(error))
  try:
    instance_desc = ec2_client.describe_instances(InstanceIds=[result["instance_id"]])
  except Exception as error:
    raise IOError("Error calling describe_instances: " + repr(error))
  result["account"] = instance_desc["Reservations"][0]["OwnerId"]
  arn = instance_desc["Reservations"][0]["Instances"][0]["IamInstanceProfile"]["Arn"]
  result["role"] = arn.split(":")[5].split("/")[1]
  env = re.search("^(" + EFConfig.VALID_ENV_REGEX + ")-", result["role"])
  if not env:
    raise IOError("Did not find environment in role name: " + result["role"])
  result["env"] = env.group(1)
  result["env_short"] = result["env"].strip(".0123456789")
  result["service"] = "-".join(result["role"].split("-")[1:])
  return result

def pull_repo():
  """
  Pulls latest version of EF_REPO_BRANCH from EF_REPO (as set in ef_config.py) if client is in EF_REPO
  and on the branch EF_REPO_BRANCH
  Raises:
    RuntimeError with message if not in the correct repo on the correct branch
  """
  try:
    current_repo = subprocess.check_output(["git", "remote", "-v", "show"])
  except subprocess.CalledProcessError as error:
    raise RuntimeError("Exception checking current repo", error)
  current_repo = re.findall("(https://|@)(.*?)(.git|[ ])", current_repo)[0][1].replace(":", "/")
  if current_repo != EFConfig.EF_REPO:
    raise RuntimeError("Must be in " + EFConfig.EF_REPO + " repo. Current repo is: " + current_repo)
  try:
    current_branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"]).rstrip()
  except subprocess.CalledProcessError as error:
    raise RuntimeError("Exception checking current branch: " + repr(error))
  if current_branch != EFConfig.EF_REPO_BRANCH:
    raise RuntimeError("Must be on branch: " + EFConfig.EF_REPO_BRANCH + ". Current branch is: " + current_branch)
  try:
    subprocess.check_call(["git", "pull", "-q", "origin", EFConfig.EF_REPO_BRANCH])
  except subprocess.CalledProcessError as error:
    raise RuntimeError("Exception running 'git pull': " + repr(error))

def create_aws_clients(region, profile, *clients):
  """
  Create boto3 clients for one or more AWS services. These are the services used within the libs:
    cloudformation, cloudfront, ec2, iam, lambda, route53, waf
  Args:
    region: the region in which to create clients that are region-specific (all but IAM)
    profile: Name of profile (in .aws/credentials). Pass the value None if using instance credentials on EC2 or Lambda
    clients: names of the clients to create (lowercase, must match what boto3 expects)
  Returns:
    A dictionary of <key>,<value> pairs for several AWS services, using the labels above as keys, e.g.:
    { "cloudfront": <cloudfront_client>, ... }
    Dictionary contains an extra record, "SESSION" - pointing to the session that created the clients
  """
  if not profile:
    profile = None

  client_key = (region, profile)

  aws_clients = client_cache.get(client_key, {})
  requested_clients = set(clients)
  new_clients = requested_clients.difference(aws_clients)

  if not new_clients:
    return aws_clients

  session = aws_clients.get("SESSION")
  try:
    if not session:
      session = boto3.Session(region_name=region, profile_name=profile)
      aws_clients["SESSION"] = session
    # build clients
    client_dict = {c: session.client(c) for c in new_clients}
    # append the session itself in case it's needed by the client code - can't get it from the clients themselves
    aws_clients.update(client_dict)

    # add the created clients to the cache
    client_cache[client_key] = aws_clients
    return aws_clients
  except ClientError as error:
    raise RuntimeError("Exception logging in with Session() and creating clients", error)

def get_account_alias(env):
  """
  Given an env, return <account_alias> if env is valid
  Args:
    env: an environment, such as "prod", "staging", "proto<N>", "mgmt.<account_alias>"
  Returns:
    the alias of the AWS account that holds the env
  Raises:
    ValueError if env is misformatted or doesn't name a known environment
  """
  env_valid(env)
  # Env is a global env of the form "env.<account_alias>" (e.g. "mgmt.<account_alias>")
  if env.find(".") > -1:
    base, ext = env.split(".")
    return ext
  # Ordinary env, possibly a proto env ending with a digit that is stripped to look up the alias
  else:
    env_short = env.strip(".0123456789")
    if env_short not in EFConfig.ENV_ACCOUNT_MAP:
      raise ValueError("generic env: {} has no entry in ENV_ACCOUNT_MAP of ef_site_config.py".format(env_short))
    return EFConfig.ENV_ACCOUNT_MAP[env_short]

def get_account_id(sts_client):
  """
  Args:
    sts_client (boto3 sts client object): Instantiated sts client object. Usually created through create_aws_clients
  """
  return sts_client.get_caller_identity().get('Account')

def get_env_short(env):
  """
  Given an env, return <env_short> if env is valid
  Args:
    env: an environment, such as "prod", "staging", "proto<N>", "mgmt.<account_alias>"
  Returns:
    the shortname of the env, such as "prod", "staging", "proto", "mgmt"
  Raises:
    ValueError if env is misformatted or doesn't name a known environment
  """
  env_valid(env)
  if env.find(".") > -1:
    env_short, ext = env.split(".")
  else:
    env_short = env.strip(".0123456789")
  return env_short

def env_valid(env):
  """
  Given an env, determine if it's valid
  Args:
    env: the env to check
  Returns:
    True if the env is valid
  Raises:
    ValueError with message if the env is not valid
  """
  if env not in EFConfig.ENV_LIST:
    raise ValueError("unknown env: {}; env must be one of: ".format(env) + ", ".join(EFConfig.ENV_LIST))
  return True

def global_env_valid(env):
  """
  Given an env, determine if it's a valid "global" or "mgmt" env as listed in EFConfig
  Args:
    env: the env to check
  Returns:
    True if the env is a valid global env in EFConfig
  Raises:
    ValueError with message if the env is not valid
  """
  if env not in EFConfig.ACCOUNT_SCOPED_ENVS:
    raise ValueError("Invalid global env: {}; global envs are: {}".format(env, EFConfig.ACCOUNT_SCOPED_ENVS))
  return True

def kms_encrypt(kms_client, service, env, secret):
  """
  Encrypt string for use by a given service/environment
  Args:
    kms_client (boto3 kms client object): Instantiated kms client object. Usually created through create_aws_clients.
    service (string): name of the service that the secret is being encrypted for.
    env (string): environment that the secret is being encrypted for.
    secret (string): value to be encrypted
  Returns:
    a populated EFPWContext object
  Raises:
    SystemExit(1): If there is an error with the boto3 encryption call (ex. missing kms key)
  """
  # Converting all periods to underscores because they are invalid in KMS alias names
  key_alias = '{}-{}'.format(env, service.replace('.', '_'))

  try:
    response = kms_client.encrypt(
      KeyId='alias/{}'.format(key_alias),
      Plaintext=secret.encode()
    )
  except ClientError as error:
    if error.response['Error']['Code'] == "NotFoundException":
      fail("Key '{}' not found. You may need to run ef-generate for this environment.".format(key_alias), error)
    else:
      fail("boto3 exception occurred while performing kms encrypt operation.", error)
  encrypted_secret = base64.b64encode(response['CiphertextBlob'])
  return encrypted_secret

def kms_decrypt(kms_client, secret):
  """
  Decrypt kms-encrypted string
  Args:
    kms_client (boto3 kms client object): Instantiated kms client object. Usually created through create_aws_clients.
    secret (string): base64 encoded value to be decrypted
  Returns:
    a populated EFPWContext object
  Raises:
    SystemExit(1): If there is an error with the boto3 decryption call (ex. malformed secret)
  """
  try:
    decrypted_secret = kms_client.decrypt(CiphertextBlob=base64.b64decode(secret))['Plaintext']
  except TypeError:
    fail("Malformed base64 string data")
  except ClientError as error:
    if error.response["Error"]["Code"] == "InvalidCiphertextException":
      fail("The decrypt request was rejected because the specified ciphertext \
      has been corrupted or is otherwise invalid.", error)
    elif error.response["Error"]["Code"] == "NotFoundException":
      fail("The decrypt request was rejected because the specified entity or resource could not be found.", error)
    else:
      fail("boto3 exception occurred while performing kms decrypt operation.", error)
  return decrypted_secret

def kms_key_arn(kms_client, alias):
  """
  Obtain the full key arn based on the key alias provided
  Args:
    kms_client (boto3 kms client object): Instantiated kms client object. Usually created through create_aws_clients.
    alias (string): alias of key, example alias/proto0-evs-drm.

  Returns:
    string of the full key arn
  """
  try:
    response = kms_client.describe_key(KeyId=alias)
    key_arn = response["KeyMetadata"]["Arn"]
  except ClientError as error:
    raise RuntimeError("Failed to obtain key arn for alias {}, error: {}".format(alias, error.response["Error"]["Message"]))

  return key_arn

def get_template_parameters_file(template_full_path):
    """
    Checks for existance of parameters file against supported suffixes and returns parameters file path if found
    Args:
      template_full_path: full filepath for template file
    Returns:
      filename of parameters file if it exists
    """
    for suffix in EFConfig.PARAMETER_FILE_SUFFIXES:
      parameters_file = template_full_path.replace("/templates", "/parameters") + suffix
      if exists(parameters_file):
        return parameters_file
      else:
        continue
    return None

def get_template_parameters_s3(template_key, s3_resource):
  """
  Checks for existance of parameters object in S3 against supported suffixes and returns parameters file key if found
  Args:
    template_key: S3 key for template file. omit bucket.
    s3_resource: a boto3 s3 resource
  Returns:
    filename of parameters file if it exists
  """
  for suffix in EFConfig.PARAMETER_FILE_SUFFIXES:
    parameters_key = template_key.replace("/templates", "/parameters") + suffix
    try:
      obj = s3_resource.Object(EFConfig.S3_CONFIG_BUCKET, parameters_key)
      obj.get()
      return parameters_key
    except ClientError:
      continue
  return None
