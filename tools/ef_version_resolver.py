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

class EFVersionResolver(object):
  """
  Resolves "the correct version" of various things, including AMIs.
  In fact, all this resolves right now is /the latest version/ of an AMI.

  Syntax:
    <thing>:<service_name>
  Example:
    ami-id:ess

  <version_type> is either the name of an environment, or "environment"
  <thing> can be:
    ami-id: the ID of the AMI for <service_name>; ami must be named "<service_name>-release"
    (others will come in the future)

  In a template:
    {{version:<thing>:<service>}}
    {{version:ami-id:ess}} <-- gets the ID of the ami for the ess service in the current environment
  """

  # dictionary of boto3 clients: {"ec2":ec2_client, ...}
  __CLIENTS = {}
  __AMI_SUFFIX = "-release"

  def ami_id(self, service_name):
    """
    Return AMI ID if found, None otherwise
    Params:
      service: name of the service
    """
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

  def lookup(self, token):
    try:
      key, value = token.split(",")
    except ValueError:
      return None
    if key == "ami-id":
      return self.ami_id(value)
    else:
      return None

  def __init__(self, clients):
    """
    ARGS
      clients - dictionary of ready-to-go boto3 clients using aws prefixes:
      expected: clients["ec2"], clients["iam"], clients["lambda"]
    """
    EFVersionResolver.__CLIENTS = clients
