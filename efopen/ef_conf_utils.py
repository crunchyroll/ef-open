"""
Configurable utility functions for ef. Configurable via EFConfig
"""
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
