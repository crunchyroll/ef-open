"""
Copyright 2016-2021 Ellation, Inc.
Copyright 2021-2022 Crunchyroll, Inc.

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
import os
import sys

import boto3
from botocore.exceptions import ClientError
import yaml

import crf_utils


class CRFSiteConfig(object):
  """
  Loads crf_site_config.yml
  """

  def __init__(self):
    self._crf_site_config = os.path.join(os.getcwd(), "crf_site_config.yml")
    self.ssm_parameter_name = os.environ.get('CRF_SSM_SITE_CONFIG_LOCATION', '/crfopen/crf_site_config')
    self.ssm_region = os.environ.get('CRF_SSM_SITE_CONFIG_REGION', 'us-west-2')

  def load(self):
    """Loads the config"""
    whereami = crf_utils.whereami()
    if whereami == 'ec2':
      try:
        return self.load_from_ssm()
      except ClientError as e:
        pass
    return self.load_from_local_file()

  def load_from_ssm(self):
    ssm = boto3.client('ssm', region_name=self.ssm_region)
    parameter_entry = ssm.get_parameter(Name=self.ssm_parameter_name)
    site_config = parameter_entry['Parameter']['Value']
    return yaml.safe_load(site_config)

  def load_from_local_file(self):
    try:
      with open(self._crf_site_config, 'r') as yml_file:
        return yaml.safe_load(yml_file)
    except (IOError, yaml.parser.ParserError) as error:
      print("Error: {}".format(error), file=sys.stderr)
      sys.exit(1)