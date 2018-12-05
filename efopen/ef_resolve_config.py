#!/usr/bin/env python

"""
Manual single file config resolver

This is mostly for testing and teaching - accepts a config file as input, finds
the matching config blob in /configs, resolves everything, and outputs the result
as it would be written to a file on an instance when starting up

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

import argparse
from ef_config import EFConfig
import ef_utils
import yaml
from os.path import abspath, dirname, normpath
import sys

from ef_template_resolver import EFTemplateResolver
from ef_utils import get_account_alias


class Context:
  def __init__(self, profile, region, env, service, template_path, no_params, verbose):
    self.profile = profile
    self.region = region
    self.env = env
    self.service = service
    self.template_path = template_path
    self.no_params = no_params
    self.param_path = ef_utils.get_template_parameters_file(self.template_path)
    self.verbose = verbose

  def __str__(self):
    return("profile: {}\nregion: {}\nenv: {}\nservice: {}\ntemplate_path: {}\nparam_path: {}\n".format(
           self.profile, self.region, self.env, self.service, self.template_path, self.param_path, self.verbose))


def handle_args_and_set_context(args):
  """
  Args:
    args: the command line args, probably passed from main() as sys.argv[1:]
  Returns:
    a populated Context object based on CLI args
  """
  parser = argparse.ArgumentParser()
  parser.add_argument("env", help="environment")
  parser.add_argument("path_to_template", help="path to the config template to process")
  parser.add_argument("--no_params", help="disable loading values from params file", action="store_true", default=False)
  parser.add_argument("--verbose", help="Output extra info", action="store_true", default=False)
  parsed = vars(parser.parse_args(args))
  path_to_template = abspath(parsed["path_to_template"])
  service = path_to_template.split('/')[-3]

  return Context(
      get_account_alias(parsed["env"]),
      EFConfig.DEFAULT_REGION,
      parsed["env"],
      service,
      path_to_template,
      parsed["no_params"],
      parsed["verbose"]
  )


def merge_files(context):
  """
  Given a context containing path to template, env, and service:
  merge config into template and output the result to stdout
  Args:
    context: a populated context object
  """
  resolver = EFTemplateResolver(
      profile=context.profile,
      region=context.region,
      env=context.env,
      service=context.service
  )

  try:
    with open(context.template_path, 'r') as f:
      template_body = f.read()
      f.close()
  except IOError as error:
    raise IOError("Error loading template file: {} {}".format(context.template_path, repr(error)))

  if context.no_params is False:
    try:
      with open(context.param_path, 'r') as f:
        param_body = f.read()
        f.close()
    except IOError as error:
      raise IOError("Error loading param file: {} {}".format(context.param_path, repr(error)))

    dest = yaml.safe_load(param_body)["dest"]

    # if 'dest' for the current object contains an 'environments' list, check it
    if "environments" in dest:
      if not resolver.resolved["ENV_SHORT"] in dest["environments"]:
        print("Environment: {} not enabled for {}".format(resolver.resolved["ENV_SHORT"], context.template_path))
        return

    # Process the template_body - apply context + parameters
    resolver.load(template_body, param_body)
  else:
    resolver.load(template_body)
  rendered_body = resolver.render()

  if not resolver.resolved_ok():
    raise RuntimeError("Couldn't resolve all symbols; template has leftover {{ or }}: {}".format(resolver.unresolved_symbols()))

  if context.verbose:
    print(context)
    if context.no_params:
      print('no_params flag set to true!')
      print('Inline template resolution based on external symbol lookup only and no destination for file write.\n')
    else:
      dir_path = normpath(dirname(dest["path"]))
      print("make directories: {} {}".format(dir_path, dest["dir_perm"]))
      print("chmod file to: " + dest["file_perm"])
      user, group = dest["user_group"].split(":")
      print("chown last directory in path to user: {}, group: {}".format(user, group))
      print("chown file to user: {}, group: {}\n".format(user, group))

    print("template body:\n{}\nrendered body:\n{}\n".format(template_body, rendered_body))
  else:
    print(rendered_body)


def main():
  context = handle_args_and_set_context(sys.argv[1:])
  merge_files(context)

if __name__ == "__main__":
  main()
