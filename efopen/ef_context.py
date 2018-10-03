# noinspection PyClassHasNoInit

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

from ef_service_registry import EFServiceRegistry
from ef_utils import env_valid, get_account_alias, get_env_short, global_env_valid, whereami

class EFContext(object):
  """
  Class holds environment/account-related context for tools and resolvers
  and helps assure consistency in, for example, trimming "env" to "env_short"
  """

  def __init__(self):
    # service environment
    self._account_alias = None
    self._env = None # the name used in AWS -- e.g. prod, proto<n>, mgmt
    self._env_short = None # the generic name -- e.g. prod, proto, mgmt
    self._env_full = None # name found in SR -- e.g. prod, proto, mgmt.<account_alias>
    self._service = None
    # Service registry object
    self._service_registry = None
    # tool context
    self._account_id = None
    self._aws_clients = None
    self._commit = None
    self._devel = None
    self._verbose = None
    self._whereami = whereami()


  @property
  def account_alias(self):
    """The account alias in use"""
    return self._account_alias

  @property
  def env(self):
    """Full name of the environment, e.g. 'prod' or 'proto3'"""
    return self._env

  @env.setter
  def env(self, value):
    """
    Sets context.env, context.env_short, and context.account_alias if env is valid
    For envs of the form "global.<account>" and "mgmt.<account_alias>",
    env is captured as "global" or "mgmt" and account_alias is parsed
    out of the full env rather than looked up
    Args:
      value: the fully-qualified env value
    Raises:
      ValueError if env is not valid
    """
    env_valid(value)
    self._env_full = value
    if value.find(".") == -1:
      # plain environment, e.g. prod, staging, proto<n>
      self._env = value
      self._account_alias = get_account_alias(value)
    else:
      # "<env>.<account_alias>" form, e.g. global.ellationeng or mgmt.ellationeng
      self._env, self._account_alias = value.split(".")
      # since we extracted an env, must reconfirm that it's legit
      global_env_valid(self._env)
    self._env_short = get_env_short(value)

  @property
  def env_short(self):
    """Short (generic) name of the environment, e.g. 'prod' or 'proto' or 'mgmt'"""
    return self._env_short

  @property
  def env_full(self):
    """Name of the environment as expected in the service registry, e.g. 'prod' or 'proto' or 'mgmt.ellationeng'"""
    return self._env_full

  @property
  def service(self):
    """A single service's object from service registry"""
    return self._service

  @service.setter
  def service(self, value):
    self._service = value

  @property
  def service_registry(self):
    """Service registry object"""
    return self._service_registry

  @service_registry.setter
  def service_registry(self, sr):
    """
    Sets service registry object in context, doesn't check it
    Args:
      sr: EFServiceRegistry object
    """
    if type(sr) is not EFServiceRegistry:
      raise TypeError("sr value must be type 'EFServiceRegistry'")
    self._service_registry = sr

  @property
  def account_id(self):
    """
    Retrieves the current account id

    Returns:
      account id (string)
    """
    return self._account_id

  @account_id.setter
  def account_id(self, value):
    """
    Sets the current account id

    Args:
      value: current account id (string)

    Returns:
      None
    """
    if type(value) is not str:
      raise TypeError("commit value must be string")
    self._account_id = value

  def aws_client(self, client_id=None):
    """
    Get AWS client if it exists (must have been formerly stored with set_aws_clients)
    If client_id is not provided, returns the dictionary of all clients
    Args:
      client_id: label for the client, e.g. 'ec2'; omit to get a dictionary of all clients
    Returns:
      aws client if found, or None if not
    """
    if client_id is None:
      return self._aws_clients
    elif self._aws_clients is not None and self._aws_clients.has_key(client_id):
      return self._aws_clients[client_id]
    else:
      return None

  def set_aws_clients(self, clients):
    """
    Stash a dictionary of AWS clients in the context object
    Args:
      clients: dictionary of clients
    """
    if type(clients) is not dict:
      raise TypeError("clients must be a dict")
    self._aws_clients = clients

  @property
  def commit(self):
    """True if the tool should actually execute changes"""
    return self._commit

  @commit.setter
  def commit(self, value):
    if type(value) is not bool:
      raise TypeError("commit value must be bool")
    self._commit = value

  @property
  def devel(self):
    """True if the tool should allow devel exceptions"""
    return self._devel

  @devel.setter
  def devel(self, value):
    if type(value) is not bool:
      raise TypeError("devel value must be bool")
    self._devel = value

  @property
  def verbose(self):
    """True if the tool should print extra info"""
    return self._verbose

  @verbose.setter
  def verbose(self, value):
    if type(value) is not bool:
      raise TypeError("verbose value must be bool")
    self._verbose = value

  @property
  def whereami(self):
    """Hosted ec2? lambda? local vm?"""
    return self._whereami
