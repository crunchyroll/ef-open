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

from ef_config import EFConfig

class EFConfigResolver(object):
  """
  Resolves values from the tool configuration in the EFConfig class (ef_config.py)

  In a template:
    {{efconfig:thing,lookup}}
    {{efconfig:accountaliasofenv,prod}} <-- gets the account alias of the account that hosts the 'prod' env
  """

  def accountaliasofenv(self, lookup):
    """
    Return account alias of the account that hosts the env named in lookup, None otherwise
    Params:
      lookup: ENV_SHORT name of an env, one of: 'prod', 'staging', or 'proto'
    """

    if EFConfig.ENV_ACCOUNT_MAP.has_key(lookup):
      return EFConfig.ENV_ACCOUNT_MAP[lookup]
    else:
      return None


  def lookup(self, token):
    try:
      key, value = token.split(",")
    except ValueError:
      return None
    if key == "accountaliasofenv":
      return self.accountaliasofenv(value)
    else:
      return None

  def __init__(self):
    pass

