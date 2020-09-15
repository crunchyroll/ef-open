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
import json
import re
import sys
import yaml

import botocore.exceptions

from ef_aws_resolver import EFAwsResolver
from ef_config import EFConfig
from ef_config_resolver import EFConfigResolver
from ef_utils import create_aws_clients, fail, get_account_id, http_get_metadata, whereami
from ef_version_resolver import EFVersionResolver

# pattern to find resolvable symbols - finds innermost nestings
symbol_pattern = re.compile(r'{{\.?([0-9A-Za-z/_,.:\-+=*]+?)}}')
# inverse of SYMBOL_PATTERN, and disallows ':' and ',' from param keys; this is checked in load()
illegal_param_chars = re.compile(r'[^(0-9A-Za-z/_.\-)]')


# Utilities
def get_metadata_or_fail(metadata_key):
  """
  Call get_metadata; halt with fail() if it raises an exception
  """
  try:
    return http_get_metadata(metadata_key)
  except IOError as error:
    fail("Exception in http_get_metadata {} {}".format(metadata_key, repr(error)))


class EFTemplateResolver(object):
  """
  Resolves {{symbol}} style tokens in a file or string from multiple sources:
    - 1. lookups of AWS resource identifiers, such as a security group ID
    - 2. secure credentials
    - 3. version registry for versioned content such as an AMI ID
    - 4. built-in context (such as "ENV")
    - 5. parameters from a parameter file / dictionary of params

  To use:
    from ef_template_resolver import EFTemplateResolver
    # if local (for testing or configuring something other than "self"):
    a = EFTemplateResolver(profile="proto", env="proto3", region="us-east-1", service="myservice")
    # if in a VM, there is no AWS context available:
    a = EFTemplateResolver(env="local", service="myservice")
    # if in EC2:
    a = EFTemplateResolver()
    # then...
    a.load(template, parameters=None, env)
    resolved = a.render() <-- multi-step resolution; returns resolved template
    if (len(a.unresolved_symbols())) > 0:
      print("Template has unresolved symbols")

  1,2,3: AWS values from the live AWS environment, and secure credential storage
    see ef_aws_resolver.py for details

  4: AWS EC2 instance or Lambda context
  These instance-state strings are always available in AWS EC2 and Lambda:
    ACCOUNT - account number in which this EC2 instance or lambda is running
    ACCOUNT_ALIAS - friendly-name alias to the numeric account number
    ENV - prod, staging, proto0..proto3, internal
    ENV_SHORT - ENV with the final digit (if any) removed to make a generic env descriptor
    FUNCTION_NAME - Lambda only
    INSTANCE_ID - EC2 only
    REGION - region in which the instance or lambda is running
    ROLE
    SERVICE - service shortname

  5: Parameter file or a dictionary of parameters
  The strings provided in a parameters file or dictionary can be any other string.
  Lowercase is recommended for template tokens, and matches are case-sensitive.
  If passing a dictionary (or creating one in a file), it's structured like the below.
  Parameter names may not contain the ":" character but can contain: / , - _ .
    {
      "params": {
        "<envA>": {
          "myvarA1": "myvalueA1",
          "myvarA2": "myvalueA2",
          ...
        },
        "<envB>": {
          "myvarA1": "myvalueA1",
          "myvarA2": "myvalueA2",
          ...
  Valid <env> values are:
    "default", "prod", "staging", "proto", "proto<0>".."proto<N>", "localvm", etc.
  <env> sections are evaluated hierarchically, in this order:
    1) "default" - optional; if present is always applied first
    2) the general environment: "prod", "staging", "proto" ("any proto<0>..<N>"), etc.
    3) "proto<N>" - the specific ephemeral environment, if any
  The ephemeral env evaluation happens to allow for example, "proto" to set generic values for all
  proto<N> environments. Then proto<N> values can be applied to specific proto envs if necessary
  to customize for the specific environment.

  """
  # class vars
  __CLIENTS = {}  # boto3 clients
  __AWSR = None   # EFAwsResolver
  __EFCR = None   # EFConfigResolver
  __VR = None     # EFVersionResolver

  def __init__(self,
               profile=None, region=None,  # set both for user access mode
               lambda_context=None,  # set if target is 'self' and this is a lambda
               target_other=False, env=None, service=None,  # set env & service if target_other=True
               skip_symbols={},
               verbose=False
               ):
    """
    Depending on how this is called, access mode (how it logs into AWS) and target (what the
      various context vars report) will vary

    ACCESS MODE - how this logs in to AWS
      user: "running on my laptop or elsewhere with a user credential"
        both 'profile' and 'region' are required
        is always "operating on something else" (TARGET is never "self")
      role: "running in AWS EC2 or Lambda with a role credential"
        do not set profile

    TARGET - what context is reported
      self: "this ec2 instance or lambda is initializing itself"
        assumed for ec2 and lambda, unless target_other=True in the constructor
        never an option for "user" access mode
      other: "this local user, ec2 instance, or lambda is configuring something else"
        always "other" if access mode is "user"
        if access mode is "role", set target_other=True in the constructor
        Constructor must also set 'env' and 'service'

      self:
        lambda_context must be provided if this is a lambda; leave it unset for ec2
        INSTANCE_ID = instance ID if EC2, else None
        FUNCTION_NAME = function name if lambda, else None
        ACCOUNT = numeric account this is running in
        ACCOUNT_ALIAS = named alias of the account this is running in
        ROLE = role this is running as
        ENV = the environment this is running in, from role name
        ENV_SHORT = derived from ENV
        ENV_FULL = fully qualified environment, same as ENV unless env is a global env (mgmt.* or global.*)
        SERVICE = the service this is, from role name
        REGION = region this is running in
      something else:
        INSTANCE_ID = None
        FUNCTION_NAME = None
        ACCOUNT = the numeric account I'm logged into (look up)
        ACCOUNT_ALIAS = the alias of the account i'm logged into (look up)
        ROLE = None
        ENV = the target's environment, passed in from the constructor
        ENV_SHORT = derived from ENV
        ENV_FULL = ENV, with ".<ACCOUNT_ALIAS>" as appropriate
        SERVICE = the service name, passed in from the constructor
        REGION = the region I am in (ec2, lambda) or explicitly set (region= in constructor)

    Collects instance's environment for use in templates:
      {{ACCOUNT}}       - AWS account number
                          CloudFormation can use this or the AWS::AccountID pseudo param
      {{ACCOUNT_ALIAS}} - AWS account alias
      {{ENV}}           - environment: mgmt, prod, staging, proto<N>, etc.
      {{ENV_SHORT}}     - env with <N> or account trimmed: mgmt, prod, staging, proto, etc.
      {{ENV_FULL}}      - env fully qualified: prod, staging, proto<N>, mgmt.<account_alias>, etc.
      {{FUNCTION_NAME}} - only for lambdas
      {{INSTANCE_ID}}   - only for ec2
      {{REGION}}        - the region currently being worked in
                          CloudFormation can use this or the AWS::Region pseudo param
      {{ROLE}}          - the role bound to the ec2 instance or lambda; only for ec2 and lambda
                          CloudFormation: compose role name in template by joining other strings
    """
    # instance vars
    self.verbose = False  # print noisy status if True
    # resolved tokens - only look up symbols once per session. Protect internal names by declaring
    self.resolved = {
        "ACCOUNT": None,
        "ACCOUNT_ALIAS": None,
        "ENV": None,
        "ENV_SHORT": None,
        "ENV_FULL": None,
        "FUNCTION_NAME": None,
        "INSTANCE_ID": None,
        "REGION": None,
        "ROLE": None
    }

    # template and parameters are populated by the load() method as each template is processed
    self.template = None
    # parameters that accompany this template, if any
    self.parameters = {}
    # Sets of symbols found in the current template (only)
    # read back with self.symbols() and self.unresolved_symbols()
    self.symbols = set()
    self.skip_symbols = skip_symbols
    # capture verbosity pref from constructor
    self.verbose = verbose

    # determine ACCESS MODE
    if profile:  # accessing as a user
      target_other = True
      if not region:
        fail("'region' is required with 'profile' for user-mode access")

    where = whereami()

    # require env and service params init() when target is 'other'
    if (target_other or where == "virtualbox-kvm") and (env is None or service is None):
      fail("'env' and 'service' must be set when target is 'other' or running in " + where)

    if target_other or profile:
      self.resolved["REGION"] = region
    # lambda initializing self
    elif lambda_context:
      self.resolved["REGION"] = lambda_context.invoked_function_arn.split(":")[3]
    # ec2 initializing self
    else:
      self.resolved["REGION"] = get_metadata_or_fail("placement/availability-zone/")[:-1]

    # Create clients - if accessing by role, profile should be None
    clients = [
      "cloudformation",
      "cloudfront",
      "cognito-identity",
      "cognito-idp",
      "dynamodb",
      "ec2",
      "ecr",
      "elbv2",
      "iam",
      "kms",
      "lambda",
      "ram",
      "route53",
      "s3",
      "sts",
      "waf"
    ]
    try:
      EFTemplateResolver.__CLIENTS = create_aws_clients(self.resolved["REGION"], profile, *clients)
    except RuntimeError as error:
      fail("Exception logging in with Session()", error)

    # Create EFAwsResolver object for interactive lookups
    EFTemplateResolver.__AWSR = EFAwsResolver(EFTemplateResolver.__CLIENTS)
    # Create EFConfigResolver object for ef tooling config lookups
    EFTemplateResolver.__EFCR = EFConfigResolver()
    # Create EFVersionResolver object for version lookups
    EFTemplateResolver.__VR = EFVersionResolver(EFTemplateResolver.__CLIENTS)

    # Set the internal parameter values for aws
    # self-configuring lambda
    if (not target_other) and lambda_context:
      arn_split = lambda_context.invoked_function_arn.split(":")
      self.resolved["ACCOUNT"] = arn_split[4]
      self.resolved["FUNCTION_NAME"] = arn_split[6]
      try:
        lambda_desc = EFTemplateResolver.__CLIENTS["lambda"].get_function()
      except:
        fail("Exception in get_function: ", sys.exc_info())
      self.resolved["ROLE"] = lambda_desc["Configuration"]["Role"]
      env = re.search("^({})-".format(EFConfig.VALID_ENV_REGEX), self.resolved["ROLE"])
      if not env:
        fail("Did not find environment in lambda function name.")
      self.resolved["ENV"] = env.group(1)
      parsed_service = re.search(self.resolved["ENV"] + "-(.*?)-lambda", self.resolved["ROLE"])
      if parsed_service:
        self.resolved["SERVICE"] = parsed_service.group(1)

    # self-configuring EC2
    elif (not target_other) and (not lambda_context):
      self.resolved["INSTANCE_ID"] = get_metadata_or_fail('instance-id')
      profile_arn = str(json.loads(http_get_metadata('iam/info'))["InstanceProfileArn"])
      self.resolved["ACCOUNT"] = profile_arn.split(":")[4]
      self.resolved["ROLE"] = profile_arn.split("/")[-1]
      self.resolved["ENV"] = self.resolved["ROLE"].split("-")[0]
      self.resolved["SERVICE"] = "-".join(self.resolved["ROLE"].split("-")[1:])

    # target is "other"
    else:
      try:
        if whereami() == "ec2":
          self.resolved["ACCOUNT"] = str(json.loads(http_get_metadata('iam/info'))["InstanceProfileArn"].split(":")[4])
        else:
          self.resolved["ACCOUNT"] = get_account_id(EFTemplateResolver.__CLIENTS["sts"])
      except botocore.exceptions.ClientError as error:
        fail("Exception in get_user()", error)
      self.resolved["ENV"] = env
      self.resolved["SERVICE"] = service

    # ACCOUNT_ALIAS is resolved consistently for access modes and targets other than virtualbox
    try:
      self.resolved["ACCOUNT_ALIAS"] = EFTemplateResolver.__CLIENTS["iam"].list_account_aliases()["AccountAliases"][0]
    except botocore.exceptions.ClientError as error:
      fail("Exception in list_account_aliases", error)

    # ENV_SHORT is resolved the same way for all access modes and targets
    self.resolved["ENV_SHORT"] = self.resolved["ENV"].strip(".0123456789")

    # ENV_FULL is resolved the same way for all access modes and targets, depending on previously-resolved values
    if self.resolved["ENV"] in EFConfig.ACCOUNT_SCOPED_ENVS:
      self.resolved["ENV_FULL"] = "{}.{}".format(self.resolved["ENV"], self.resolved["ACCOUNT_ALIAS"])
    else:
      self.resolved["ENV_FULL"] = self.resolved["ENV"]

    if self.verbose:
      print(repr(self.resolved), file=sys.stderr)

  def load(self, template, parameters=None):
    """
    'template'
    Loads template text from a 'string' or 'file' type
    Template text contains {{TOKEN}} symbols to be replaced

    'parameters'
    parameters contains environment-specific sections as discussed in the class documentation.
    the 'parameters' arg can be None, a 'string', 'file', or 'dictionary'

    Whether from a string or file, or already in a dictionary, parameters must follow the
    logical format documented in the class docstring.
    if 'parameters' is omitted, template resolution will proceed with AWS, credential, and
    version lookups.
    """
    # load template
    if isinstance(template, str):
      self.template = template
    elif isinstance(template, file):
      try:
        self.template = template.read()
        template.close()
      except IOError as error:
        fail("Exception loading template from file: ", error)
    else:
      fail("Unknown type loading template; expected string or file: " + type(template))

    # load parameters, if any
    if parameters:
      if isinstance(parameters, str):
        try:
          self.parameters = yaml.safe_load(parameters)
        except ValueError as error:
          fail("Exception loading parameters from string: ", error)
      elif isinstance(parameters, file):
        try:
          self.parameters = yaml.safe_load(parameters)
          parameters.close()
        except ValueError as error:
          fail("Exception loading parameters from file: {}".format(error), sys.exc_info())
      elif isinstance(parameters, dict):
        self.parameters = parameters
      else:
        fail("Unknown type loading parameters; expected string, file, or dict: " + type(parameters))
      # sanity check the loaded parameters
      if "params" not in self.parameters:
        fail("'params' field not found in parameters")
      # just the params, please
      self.parameters = self.parameters["params"]
      # are all the keys valid (must have legal characters)
      for k in set().union(*(self.parameters[d].keys() for d in self.parameters.keys())):
        invalid_char = illegal_param_chars.search(k)
        if invalid_char:
          fail("illegal character: '" + invalid_char.group(0) + "' in parameter key: " + k)

  def search_parameters(self, symbol):
    """
    Hierarchically searches for 'symbol' in the parameters blob if there is one (would have
    been retrieved by 'load()'). Order is: default, <env_short>, <env>
    Returns
      Hierarchically resolved value for 'symbol', or None if a match is not found or there are no parameters
    """
    if not self.parameters:
      return None
    # Hierarchically lookup the key
    result = None
    if "default" in self.parameters and symbol in self.parameters["default"]:
      result = self.parameters["default"][symbol]
    if self.resolved["ENV_SHORT"] in self.parameters and symbol in self.parameters[self.resolved["ENV_SHORT"]]:
      result = self.parameters[self.resolved["ENV_SHORT"]][symbol]
    # This lookup is redundant when env_short == env_full, but it's also cheap. Also handles the case for mgmt.<account_alias>
    if self.resolved["ENV_FULL"] in self.parameters and symbol in self.parameters[self.resolved["ENV_FULL"]]:
      result = self.parameters[self.resolved["ENV_FULL"]][symbol]
    return result

  def render(self):
    """
    Find {{}} tokens; resolve then replace them as described elsewhere
    Resolution is multi-pass: tokens may be nested to form parts of other tokens.

    Token search steps when resolving symbols
      - 1. lookups of AWS resource identifiers, such as a security group ID
      - 2. secure credentials
      - 3. version registry for versioned content such as an AMI ID
      - 4. built-in context (such as "ENV")
      - 5. parameters from a parameter file / dictionary of params
    """
    # Ensure that our symbols are clean and are not from a previous template that was rendered
    self.symbols = set()
    # Until all symbols are resolved or it is determined that some cannot be resolved, repeat:
    go_again = True
    while go_again:
      go_again = False  # if at least one symbol isn't resolved in a pass, stop
      # Gather all resolvable symbols in the template
      template_symbols = set(symbol_pattern.findall(self.template))
      self.symbols.update(template_symbols)  # include this pass's symbols in full set
      # resolve and replace symbols
      for symbol in template_symbols:
        resolved_symbol = None

        # Don't resolve symbols that are provided as skippable
        if symbol.split(',')[0] in self.skip_symbols:
          resolved_symbol = "SKIPPED_SYMBOL"
        # Lookups in AWS, only if we have an EFAwsResolver
        elif symbol[:4] == "aws:" and EFTemplateResolver.__AWSR:
          resolved_symbol = EFTemplateResolver.__AWSR.lookup(symbol[4:])
        # Lookups in credentials
        elif symbol[:12] == "credentials:":
          pass  #TODO
        elif symbol[:9] == "efconfig:":
          resolved_symbol = EFTemplateResolver.__EFCR.lookup(symbol[9:])
        elif symbol[:8] == "version:":
          resolved_symbol = EFTemplateResolver.__VR.lookup(symbol[8:])
          if not resolved_symbol:
            print("WARNING: Lookup failed for {{%s}} - placeholder value of 'NONE' used in rendered template" % symbol)
            resolved_symbol = "NONE"
        else:
          # 1. context - these are already in the resolved table
          # self.resolved[symbol] may have value=None; use has_key tell "resolved w/value=None" from "not resolved"
          # these may be "global" symbols such like "ENV", "ACCOUNT", etc.
          if symbol in self.resolved:
            resolved_symbol = self.resolved[symbol]
          # 2. parameters
          if not resolved_symbol:
            resolved_symbol = self.search_parameters(symbol)
        # if symbol was resolved, replace it everywhere
        if resolved_symbol is not None:
          if isinstance(resolved_symbol, list):
            # Using old style of string formatting here due to str.format() interaction with curly braces
            self.template = re.sub(r'{{\.?%s}}' % re.escape(symbol), "\n".join(resolved_symbol), self.template)
          else:
            self.template = re.sub(r'{{\.?%s}}' % re.escape(symbol), resolved_symbol, self.template)
          go_again = True
    return self.template

  def unresolved_symbols(self):
    return set(symbol_pattern.findall(self.template))

  def count_braces(self):
    """
    returns a count of "{{" and "}}" in the template, as (N_left_braces, N_right_braces)
    Useful to check after resolve() has run, to infer that template has an error since no {{ or }}
    should be present in the template after resolve()
    """
    n_left = len(re.findall("{{", self.template))
    n_right = len(re.findall("}}", self.template))
    return n_left, n_right

  def resolved_ok(self):
    """
    Shortcut to testing unresolved_symbols and count_braces separately.
    Returns false if there are unresolved symbols or {{ or }} braces remaining, true otherwise
    """
    left_braces, right_braces = self.count_braces()
    return len(self.unresolved_symbols()) == left_braces == right_braces == 0
