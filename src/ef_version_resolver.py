"""
Copyright 2016 Ellation, Inc.

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

from operator import itemgetter
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
  __AMI_SUFFIX = "-release"

  def _getlatest_ami_id(self, env, service_name):
    try:
      response = EFVersionResolver.__CLIENTS["ec2"].describe_images(
        Filters=[
          {"Name": "is-public", "Values": ["false"]},
          {"Name": "name", "Values": [service_name + EFVersionResolver.__AMI_SUFFIX + "*"]}
        ])
    except:
      return None
    if len(response["Images"]) > 0:
      return sorted(response["Images"], key=itemgetter('CreationDate'), reverse=True)[0]["ImageId"]
    else:
      return None

  def _s3_get(self, env, service, key, norecurse=False):
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
    s3_value = s3_object["Body"].read().decode(EFConfig.S3_VERSION_CONTENT_ENCODING)
    if norecurse or s3_value not in EFConfig.SPECIAL_VERSIONS:
      return s3_value
    if s3_value == "=prod":
      return self._s3_get("prod", service, key)
    elif s3_value == "=staging":
      return self._s3_get("staging", service, key)
    elif s3_value == "=latest":
      method_name = "_getlatest_" + key.replace("-", "_")
      if hasattr(self, method_name):
        return getattr(self, method_name)(env, service)
      else:
        raise RuntimeError("version for {}/{} is '=latest' but can't look up because method not found: {}".format(
          env, service, method_name))

  def lookup(self, token):
    """
    Return AMI ID if found, None otherwise
    Lookup should look like this:
      pattern:
      <key>[/norecurse],<env>/<service>
      example:
      ami-id,staging/core
      ami-id/norecurse,staging/core
    """
    # get search key, either "key," or "key/norecurse,"
    try:
      key, envservice = token.split(",")
    except ValueError:
      return None
    # separate key/norecurse if they exist
    norecurse = str(key).endswith("/norecurse")
    if norecurse:
      key = key.split("/")[0]
    # get env, service from value
    try:
      env, service = envservice.split("/")
    except ValueError as e:
      raise RuntimeError("Request:{} can't resolve to env, service. {}".format(envservice, e.message))

    return self._s3_get(env, service, key, norecurse)

  def __init__(self, clients):
    """
    ARGS
      clients - dictionary of ready-to-go boto3 clients using aws prefixes:
      expected: clients["ec2", "iam", "lambda", "s3"]
    """
    EFVersionResolver.__CLIENTS = clients
