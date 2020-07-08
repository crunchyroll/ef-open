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
from collections import namedtuple
import json
from os import access, getenv, X_OK
from os.path import isfile
import re
from socket import gethostname
import subprocess
import sys
import urllib2

import boto3
from botocore.exceptions import ClientError

__HTTP_DEFAULT_TIMEOUT_SEC = 5
__METADATA_PREFIX = "http://169.254.169.254/latest/meta-data/"
__VIRT_WHAT = "/sbin/virt-what"
__VIRT_WHAT_VIRTUALBOX_WITH_KVM = ["virtualbox", "kvm"]

# Matches CIDRs (loosely, TBH)
CIDR_REGEX = r"^(([1-2][0-9]{2}|[0-9]{0,2})\.){3}([1-2][0-9]{2}|[0-9]{0,2})\/([1-3][0-9]|[0-9])$"

# Cache for AWS clients. Keeps all the clients under (region, profile) keys.
client_cache = {}

DecryptedSecret = namedtuple("DecryptedSecret", ["plaintext", "key_id"])


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
    "jenkins" - running inside a Jenkins job
    "virtualbox-kvm" - kernel VM (virtualbox with vagrant)
    "local" - running locally and not in a known VM
    "unknown" - I have no idea where I am
  """
  if getenv("JENKINS_URL") and getenv("JENKINS_DOCKER") is None:
    # The addition of the JENKINS_DOCKER is a temporary workaround to have Jenkins Docker machine rely on its instance
    # role and assume roles vs a credentials file. This is an on-going effort to move everything to code with
    # https://ellation.atlassian.net/browse/OPS-13637
    # Regular Jenkins machines will still continue to use their credentials files until we switch over.
    return "jenkins"

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

def get_account_id(sts_client):
  """
  Args:
    sts_client (boto3 sts client object): Instantiated sts client object. Usually created through create_aws_clients
  """
  return sts_client.get_caller_identity().get('Account')

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
    DecryptedSecret object
  Raises:
    SystemExit(1): If there is an error with the boto3 decryption call (ex. malformed secret)
  """
  try:
    response = kms_client.decrypt(CiphertextBlob=base64.b64decode(secret))
    decrypted_secret = DecryptedSecret(response["Plaintext"], response["KeyId"])
  except TypeError as e:
    fail("Malformed base64 string data: {}".format(e))
  except ClientError as error:
    if error.response["Error"]["Code"] == "InvalidCiphertextException":
      fail("The decrypt request was rejected because the specified ciphertext \
      has been corrupted or is otherwise invalid.", error)
    elif error.response["Error"]["Code"] == "NotFoundException":
      fail("The decrypt request was rejected because the specified entity or resource could not be found.", error)
    else:
      fail("boto3 exception occurred while performing kms decrypt operation.", error)
  return decrypted_secret

def kms_re_encrypt(kms_client, service, env, secret):
  """
  Re-encrypt the secret for a new service. Don't need to know the plaintext
  Args:
    kms_client (boto3 kms client object): Instantiated kms client object. Usually created through create_aws_clients.
    service (string): name of the service that the secret is being encrypted for.
    env (string): environment that the secret is being encrypted for.
    secret (string): base64 encoded value to be reencrypted
  Returns:
    a populated EFPWContext object
  Raises:
    SystemExit(1): If there is an error with the boto3 encryption call (ex. missing kms key)
  """
  # Converting all periods to underscores because they are invalid in KMS alias names
  key_alias = '{}-{}'.format(env, service.replace('.', '_'))

  try:
    response = kms_client.re_encrypt(
      DestinationKeyId='alias/{}'.format(key_alias),
      CiphertextBlob=base64.b64decode(secret)
    )
  except TypeError as e:
    fail("Malformed base64 string data: {}".format(e))
  except ClientError as error:
    if error.response['Error']['Code'] == "NotFoundException":
      fail("Key '{}' not found. You may need to run ef-generate for this environment.".format(key_alias), error)
    else:
      fail("boto3 exception occurred while performing kms encrypt operation.", error)
  encrypted_secret = base64.b64encode(response['CiphertextBlob'])
  return encrypted_secret

def kms_key_alias(kms_client, key_arn):
  """
  Obtain the key aliases based on the key arn provided
  Args:
    kms_client (boto3 kms client object): Instantiated kms client object. Usually created through create_aws_clients.
    key_arn (string): key arn

  Returns:
    list of aliases associated with the key
  """
  try:
    response = kms_client.list_aliases(KeyId=key_arn)
    key_aliases = [key_data["AliasName"] for key_data in response["Aliases"]]
    clean_aliases = [alias.split('/', 1)[1] for alias in key_aliases]
  except ClientError as error:
    raise RuntimeError("Failed to obtain key alias for arn {}, error: {}".format(key_arn, error.response["Error"]["Message"]))

  return clean_aliases

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

def get_autoscaling_group_properties(asg_client, env, service):
  """
  Gets the autoscaling group properties based on the service name that is provided. This function will attempt the find
  the autoscaling group base on the following logic:
    1. If the service name provided matches the autoscaling group name
    2. If the service name provided matches the Name tag of the autoscaling group
    3. If the service name provided does not match the above, return None
  Args:
    clients: Instantiated boto3 autoscaling client
    env: Name of the environment to search for the autoscaling group
    service: Name of the service
  Returns:
    JSON object of the autoscaling group properties if it exists
  """
  try:
    # See if {{ENV}}-{{SERVICE}} matches ASG name
    response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=["{}-{}".format(env, service)])
    if len(response["AutoScalingGroups"]) == 0:
      # See if {{ENV}}-{{SERVICE}} matches ASG tag name
      response = asg_client.describe_tags(Filters=[{ "Name": "Key", "Values": ["Name"] }, { "Name": "Value", "Values": ["{}-{}".format(env, service)]}])
      if len(response["Tags"]) == 0:
        # Query does not match either of the above, return None
        return None
      else:
         asg_name = response["Tags"][0]["ResourceId"]
         response = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
         return response["AutoScalingGroups"]
    else:
      return response["AutoScalingGroups"]
  except ClientError as error:
    raise RuntimeError("Error in finding autoscaling group {} {}".format(env, service), error)
