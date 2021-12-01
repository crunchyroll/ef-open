"""
Copyright 2016-2017 Crunchyroll, Inc.

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
import yaml


class CRFSiteConfig(object):
  """
  Loads crf_site_config.yml
  """

  def __init__(self):
    self._crf_site_config = os.path.join(os.path.dirname(__file__), '../test_data/crf_site_config.yml')

  def load(self):
    """Loads the config"""
    try:
      with open(self._crf_site_config, 'r') as yml_file:
        return yaml.safe_load(yml_file)
    except (IOError, yaml.parser.ParserError) as error:
      print("Error: {}".format(error), file=sys.stderr)
      sys.exit(1)
