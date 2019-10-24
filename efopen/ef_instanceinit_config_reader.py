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

from os import walk
import yaml

import botocore.exceptions

from ef_config import EFConfig
import ef_utils
import ef_conf_utils


class EFInstanceinitConfigReader:
  """
  Reads a set of local configs files and parameters, stored locally as files or in s3
  Config_Reader.next() advances to the next item, or returns False if there are no more
  Args:
    service: name of the service
    base_path: path to TLD of all configs that should be loaded
  """

  def __init__(self, service, base_path, logger, s3_resource=None):
    """
    Args:
      service: "s3" or "file" -- use S3 in AWS, and "file" in local dev
      base_path: prefix of the path to the config bucket:
        for s3: "all" or "<service>"
        for file: "/vagrant/configs/<"all"|<service>>
      logger: an function that will log messages from here
      s3_resource: if s3, a boto3 s3 resource
    """
    self.service = service
    self.base_path = base_path
    self.logger = logger
    self.s3_resource = s3_resource
    self.template_prefix = self.base_path + "/templates/"
    self.current = None

    self.items = []
    if self.service == "s3":
      bucket = self.s3_resource.Bucket(EFConfig.S3_CONFIG_BUCKET)
      bucket_objects = bucket.objects.filter(Prefix=self.template_prefix)
      # unpack into a list for easier iteration
      for bucket_object in bucket_objects:
        self.items.append(bucket_object)
    elif self.service == "file":
      for _path, _dir, _files in walk(self.template_prefix):
        for _file in _files:
          self.items.append("{}{}".format(_path, _file))
    else:
      raise ValueError("invalid service: {} in EFInstanceinitConfigReader; valid: 's3','file'".format(self.service))

  def next(self):
    if len(self.items) <= 0:
      return False
    self.current = self.items.pop()
    self.logger("next item: " + repr(self.current))
    # S3
    if self.service == "s3":
      # the S3 set contains path entries with length 0; skip them
      while self.current.size == 0:
        if len(self.items) < 1:
          return False
        self.current = self.items.pop()
    return True

  @property
  def template(self):
    if self.service == "s3":
      try:
        self.logger("Loading template object: " + self.current.key)
        return self.current.get()['Body'].read()
      except botocore.exceptions.ClientError as error:
        raise IOError("Error loading template at key: {} {}".format(self.current.key, repr(error)))
    elif self.service == "file":
      self.logger("Loading template file: {}".format(self.current))
      try:
        return open(self.current).read()
      except Exception as error:
        raise IOError("Error loading template file: {} {}".format(self.current, repr(error)))

  @property
  def parameters(self):
    if self.service == "s3":
      key = ef_conf_utils.get_template_parameters_s3(self.current.key, self.s3_resource)
      self.logger("Loading parameters object: {}".format(key))
      try:
        obj = self.s3_resource.Object(EFConfig.S3_CONFIG_BUCKET, key)
        body = obj.get()['Body'].read()
        return yaml.safe_load(body)
      except botocore.exceptions.ClientError as error:
        raise IOError("Error loading parameters from: {} {}".format(key, repr(error)))
    elif self.service == "file":
      parameters_file = ef_conf_utils.get_template_parameters_file(self.current)
      self.logger("Loading parameters file: {}".format(self.current))
      try:
        return yaml.safe_load(file(parameters_file))
      except Exception as error:
        raise IOError("Error loading parameters file: {} {}".format(parameters_file, repr(error)))

  @property
  def dest(self):
    return self.parameters["dest"]

  @property
  def current_key(self):
    if self.service == "s3":
      return self.current.key
    elif self.service == "file":
      return self.current
