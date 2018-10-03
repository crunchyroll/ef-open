"""
Copyright 2016-2018 Ellation, Inc.

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

  def accountaliasofenv(self, lookup, default=None):
    """
    Args:
      lookup: ENV_SHORT name of an env, such as: 'prod' or 'proto'
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The account alias of the account that hosts the env named in lookupor default/None if no match found
    """
    if lookup in EFConfig.ENV_ACCOUNT_MAP:
      return EFConfig.ENV_ACCOUNT_MAP[lookup]
    else:
      return None

  def customdata(self, lookup, default=None):
    """
    Args:
      lookup: the custom data file
      default: the optional value to return if lookup failed; returns None if not set
    Returns:
      The custom data returned from the file 'lookup' or default/None if no match found
    """
    try:
      if lookup in EFConfig.CUSTOM_DATA:
        return EFConfig.CUSTOM_DATA[lookup]
      else:
        return default
    except AttributeError:
      return default

  def lookup(self, token):
    try:
      kv = token.split(",")
    except ValueError:
      return None
    if kv[0] == "accountaliasofenv":
      return self.accountaliasofenv(*kv[1:])
    if kv[0] == "customdata":
      return self.customdata(*kv[1:])
    else:
      return None

  def __init__(self):
    pass
