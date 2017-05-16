"""
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

from botocore.client import ClientError

from ef_config import EFConfig

class EFVersionResolver(object):
  """
  Resolves "the correct version" of various things, including AMIs.
  In fact, all this resolves right now is /the latest version/ of an AMI.

  Syntax:
    <thing>,<env>/<service_name>
  Example:
    ami-id,prod/ess

  <thing> can be:
    ami-id: the ID of the AMI for <service_name>; ami must be named "<service_name>-release"
    (others will come in the future)

  In a template:
    {{version:<thing>,<env>/<service>}}
    {{version:ami-id,staging/ess}} <-- gets the ID of the ami for the ess service in the current environment

  Requires these clients:
    clients["ec2", "iam", "lambda", "s3"]
  """

  # dictionary of boto3 clients: {"ec2":ec2_client, ...}
  __CLIENTS = {}

  def _s3_get(self, env, service, key):
    s3_key = "{}/{}/{}".format(service, env, key)
    try:
      s3_object = EFVersionResolver.__CLIENTS["s3"].get_object(
        Bucket = EFConfig.S3_VERSION_BUCKET,
        Key = s3_key
      )
    except ClientError as e:
      # If object was legit not found, return None. This is not a failure.
      # Allows precheck to continue for bootstrapping, and the template resolver expects None in this case
      response_code = e.response["ResponseMetadata"]["HTTPStatusCode"]
      if response_code == 404:
        return None
      # Otherwise, an unexpected issue occurred. Stop with error
      raise
    # Else get the value and decide what to do with it
    return s3_object["Body"].read().decode(EFConfig.S3_VERSION_CONTENT_ENCODING)

  def lookup(self, token):
    """
    Return key version if found, None otherwise
    Lookup should look like this:
      pattern:
      <key>,<env>/<service>
      example:
      ami-id,staging/core
    """
    # get search key and env/service from token
    try:
      key, envservice = token.split(",")
    except ValueError:
      return None
    # get env, service from value
    try:
      env, service = envservice.split("/")
    except ValueError as e:
      raise RuntimeError("Request:{} can't resolve to env, service. {}".format(envservice, e.message))

    return self._s3_get(env, service, key)

  def __init__(self, clients):
    """
    ARGS
      clients - dictionary of ready-to-go boto3 clients using aws prefixes:
      expected: clients["ec2", "iam", "lambda", "s3"]
    """
    EFVersionResolver.__CLIENTS = clients
