"""
Configurable utility functions for ef. Configurable via EFConfig
"""
import re
import subprocess

from os.path import exists

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
      else:
        continue
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
  Pulls latest version of EF_REPO_BRANCH from EF_REPO (as set in ef_config.py) if client is in EF_REPO
  and on the branch EF_REPO_BRANCH
  Raises:
    RuntimeError with message if not in the correct repo on the correct branch
  """
  try:
    current_repo = subprocess.check_output(["git", "remote", "-v", "show"])
  except subprocess.CalledProcessError as error:
    raise RuntimeError("Exception checking current repo", error)
  current_repo = re.findall("(https://|@)(.*?)(.git|[ ])", current_repo)[0][1].replace(":", "/")
  if current_repo != EFConfig.EF_REPO:
    raise RuntimeError("Must be in " + EFConfig.EF_REPO + " repo. Current repo is: " + current_repo)
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
