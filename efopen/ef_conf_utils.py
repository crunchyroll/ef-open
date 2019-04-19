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
