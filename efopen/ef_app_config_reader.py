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

import yaml

import botocore.exceptions

from ef_config import EFConfig
from ef_utils import get_env_short


class EFAppConfigReader:
  """
  Reads one set of env-based configs (one object) directly from a S3 for use by an app (no file overlaying).
  Perform hierarchical env-based config overlaying (least-specific to most)
  e.g.: default (if present) - superseded by proto (if present) - superseded by proto<N> (if present)
  or: default (if present) - superseded by staging or prod (if present)
  """

  def __init__(self, env, service, clients):
    """
    Args:
      env: the environment to resolve values for
      service: "all" or "<service">
      clients: a dict of AWS clients, with at least "s3"
    Raises:
      botocore.exceptions.ClientError if config
    """
    self.clients = clients
    self.env = env
    self.env_short = get_env_short(env)
    self.parameters = None
    self.service = service

    # Load from S3
    parameters_key = self.service + "/parameters/" + self.service + ".parameters.json"
    try:
      parameters_object = self.clients["s3"].get_object(
        Bucket=EFConfig.S3_CONFIG_BUCKET,
        Key=parameters_key
      )
    except botocore.exceptions.ClientError:
      raise RuntimeError("Error getting parameters from key: {}".format(parameters_key))
    self.parameters = yaml.safe_load(parameters_object["Body"].read().decode("utf-8"))["params"]

  def __repr__(self):
    keys = set()
    for env in self.parameters.keys():
      keys.update(self.parameters[env].keys())
    result = ""
    for key in keys:
      result = result + "{}: {}\n".format(key, self.get_value(key))
    return result

  def get_value(self, symbol):
    """
    Hierarchically searches for 'symbol' in the parameters blob if there is one (would have
    been retrieved by 'load()'). Order is: default, <env_short>, <env>
    Args:
      symbol: the key to resolve
    Returns:
      Hierarchically resolved value for 'symbol' in the environment set by the constructor,
      or None if a match is not found or there are no parameters
    """
    default = "default"
    if not self.parameters:
      return None
    # Hierarchically lookup the value
    result = None
    if default in self.parameters and symbol in self.parameters[default]:
      result = self.parameters[default][symbol]
    if self.env_short in self.parameters and symbol in self.parameters[self.env_short]:
      result = self.parameters[self.env_short][symbol]
    # This lookup is redundant when env_short == env, but it's also cheap
    if self.env in self.parameters and symbol in self.parameters[self.env]:
      result = self.parameters[self.env][symbol]
    # Finally, convert any list of items into a single \n-delimited string
    if isinstance(result, list):
      result = "\n".join(result)

    return result


# @todo: proper test coverage for this module
# In lieu of that for the moment, this demonstration code:
import boto3


def main():
  session = boto3.Session(profile_name="ellationeng", region_name="us-west-2")
  clients = {"s3": session.client("s3")}
  configreader = EFAppConfigReader("staging", "qc-pulls", clients)
  print("remote username")
  print(configreader.get_value("remote_username"))


if __name__ == "__main__":
  main()
