"""
Configurable utility functions for ef. Configurable via EFConfig
"""
import re
import subprocess
from os.path import exists

from botocore.exceptions import ClientError

from ef_config import EFConfig

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
    return None

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

def pull_repo():
  """
  Pulls latest version of EF_REPO_BRANCH
  Raises:
    RuntimeError with message if not on the correct branch
  """
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
