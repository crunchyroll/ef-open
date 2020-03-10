#!/usr/bin/env python
"""
Validates service json configuration templates and/or Cloudformation parameter files

Exit codes:
  0 if all tested configs were valid
  1 if one or more tested configs had errors
  2 if an I/O error occurred when processing a file
  3 if some other error occurred


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
import json
from os import walk
import os.path
import sys

CONFIGS_RELATIVE_PATH_FROM_SCRIPT_DIR = "../configs"
PARAMETER_SUFFIX = ".parameters.json"
DEFAULT_LOGFILE = "/tmp/instanceinit.log"

def handle_args(args):
  """
  Handle command line arguments
  Raises:
    Exception if the config path wasn't explicitly state and dead reckoning based on script location fails
  """
  parser = argparse.ArgumentParser(description="Check if a late bind config is valid or not.")
  parser.add_argument("configpath", default=None, nargs="?",
                      help="/path/to/configs (always a directory; if omitted, all /configs are checked")
  parser.add_argument("--verbose", action="store_true", default=False)
  parsed_args = vars(parser.parse_args(args))
  # If a config path wasn't given, calculate it based on location of the script
  if parsed_args["configpath"] is None:
    script_dir = os.path.abspath(os.path.dirname(sys.argv[0]))
    parsed_args["configpath"] = os.path.normpath("{}/{}".format(script_dir, CONFIGS_RELATIVE_PATH_FROM_SCRIPT_DIR))
  else:
    parsed_args["configpath"] = os.path.normpath(parsed_args["configpath"])
  # If the path is a directory, all good. if it's a file, find the directory the file is in and check that instead
  if os.path.isdir(parsed_args["configpath"]):
    parsed_args["configdir"] = parsed_args["configpath"]
  else:
    parsed_args["configdir"] = os.path.dirname(parsed_args["configpath"])
  return parsed_args

def load_json(json_filespec):
  """
  Loads JSON from a config file
  Args:
    json_filespec: path/to/file.json
  Returns:
    a dict made from the JSON read, if successful
  Raises:
    IOError if the file could not be opened
    ValueError if the JSON could not be read successfully
    RuntimeError if something else went wrong
  """
  json_fh = open(json_filespec)
  config_dict = json.load(json_fh)
  json_fh.close()
  return config_dict

def check_file(json_filespec):
  load_json(json_filespec)


def main():
  args = handle_args(sys.argv[1:])
  if args["verbose"]:
    print("Path: {}".format(args["configpath"]))
    print("Dir: {}".format(args["configdir"]))

  # Confirm that all parameters files can be loaded
  exit_code = 0
  for root, dirs, files in walk(args["configdir"]):
    for f in files:
      filename = os.path.join(root, f)
      # dot-files aren't checked
      if filename.startswith("."):
        continue
      # Only 'parameters' files, not templates
      if not os.path.dirname(filename).endswith("/parameters"):
        continue
      if args["verbose"]:
        print(filename)
      try:
        check_file(filename)
      except ValueError:
        print("JSON syntax error: {}".format(filename))
        exit_code = 1
      except IOError as e:
        print("IO error processing file:\n{}\n{}".format(filename, e))
        sys.exit(2)
      except Exception as e:
        print("Exception processing file:\n{}\n{}".format(filename, e))
        sys.exit(3)

  sys.exit(exit_code)

if __name__ == "__main__":
  main()
