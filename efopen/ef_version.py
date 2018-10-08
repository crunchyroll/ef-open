#!/usr/bin/env python

"""
Utility to change entries in the version registry.
Expects these permissions (for the /current account/ only -- prod and non-prod are segregated)
  - GetObject (to retrieve a version)
  - GetObjectVersion (to retrieve a specific version of an object)
  - ListBucket (to retrieve objects including versions of objects
  - ListBucketVersions (which allows listing /Object/ versions)
  - PutObject (to update an object)

Syntax:
  ef-version <service> <key> <env> --get
  ef-version <service> <key> <env> --set <value> --commit
  ef-version <service> <key> <env> --set =prod --commit
  ef-version <service> <key> <env> --set =staging --commit
  ef-version <service> <key> <env> --set =latest --commit

Service registry must be reachable for --set; isn't needed for  --get*
If doing --set, must run from within the repo so app can auto-locate the service registry file

Known issues:
  Race condition if independent read/set occurs on a key before S3 update is fully consistent
"""

from __future__ import print_function
import argparse
from inspect import isfunction
import json
from operator import itemgetter
from os import getenv
import sys
import urllib2

from botocore.exceptions import ClientError

from ef_config import EFConfig
from ef_context import EFContext
from ef_service_registry import EFServiceRegistry
from ef_utils import create_aws_clients, fail, pull_repo
from ef_version_resolver import EFVersionResolver

VERBOSE = False

class EFVersionContext(EFContext):
  def __init__(self):
    super(EFVersionContext, self).__init__()
    # core stuff
    self._build_number = None
    self._commit_hash = None
    self._force_env_full = None
    self._get = None
    self._history = None
    self._key = None
    self._location = None
    self._limit = None
    self._noprecheck = None
    self._rollback = None
    self._service_name = None # Cheating - we don't care about the full service record so don't use context.service
    self._show = None
    self._stable = None
    self._value = None
    self._versionresolver = None

  @property
  def build_number(self):
    """Externally defined build number assoicated with version entity"""
    return self._build_number

  @build_number.setter
  def build_number(self, value):
    """Setter provided because this is writeable from other than init() because --rollback alters it"""
    self._build_number = value

  @property
  def commit_hash(self):
    """Commit hash associated with version entity"""
    return self._commit_hash

  @commit_hash.setter
  def commit_hash(self, value):
    """Setter provided because this is writeable from other than init() because --rollback alters it"""
    self._commit_hash = value

  @property
  def get(self):
    """True if we are 'getting' the latest version value. --get was selected"""
    return self._get

  @EFContext.env.getter
  def env(self):
    """Returns env or overrides the env value with env full if --env_full was selected"""
    if self._force_env_full:
      return self.env_full
    return self._env

  @property
  def history(self):
    return self._history

  @property
  def key(self):
    """The key being manipulated"""
    return self._key

  @property
  def location(self):
    """Location (URL) where version is deployed and can be lookup up"""
    return self._location

  @location.setter
  def location(self, value):
    """Setter provided because this is writeable from other than init() because --rollback alters it"""
    self._location = value

  @property
  def limit(self):
    """Limit to number of records to return"""
    return self._limit

  @limit.setter
  def limit(self, value):
    """Limit is changed sometimes by internal calls"""
    self._limit = value

  @property
  def noprecheck(self):
    return self._noprecheck

  @property
  def rollback(self):
    return self._rollback

  @property
  def service_name(self):
    """The service being queried or set (name only, since gets don't use the service registry"""
    return self._service_name

  @property
  def show(self):
    """True if --show was set"""
    return self._show

  @property
  def stable(self):
    return self._stable

  @stable.setter
  def stable(self, value):
    """Setter provided because this is writeable from other than init() because --rollback alters it"""
    self._stable = value

  @property
  def value(self):
    """The value read from the key (for a get) or to assign to the key (for a set)"""
    return self._value

  @value.setter
  def value(self, value):
    """Setter provided because this is writeable from other than init() because --rollback alters it"""
    self._value = value

  @property
  def versionresolver(self):
    """An instantiated ef_versionresolver"""
    return self._versionresolver


class Version(object):
  """
  Holds one 'object version' at a time, provides it in several formats
  """

  def __init__(self, object_version):
    if EFConfig.S3_VERSION_BUILDNUMBER_KEY in object_version["Metadata"]:
      self._build_number = object_version["Metadata"][EFConfig.S3_VERSION_BUILDNUMBER_KEY]
    else:
      self._build_number = ""
    if EFConfig.S3_VERSION_COMMITHASH_KEY in object_version["Metadata"]:
      self._commit_hash = object_version["Metadata"][EFConfig.S3_VERSION_COMMITHASH_KEY]
    else:
      self._commit_hash = ""
    self._last_modified = object_version["LastModified"].strftime("%Y-%m-%dT%H:%M:%S%Z")
    if EFConfig.S3_VERSION_LOCATION_KEY in object_version["Metadata"]:
      self._location = object_version["Metadata"][EFConfig.S3_VERSION_LOCATION_KEY]
    else:
      self._location = ""
    if EFConfig.S3_VERSION_MODIFIEDBY_KEY in object_version["Metadata"]:
      self._modified_by = object_version["Metadata"][EFConfig.S3_VERSION_MODIFIEDBY_KEY]
    else:
      self._modified_by = ""
    if EFConfig.S3_VERSION_STATUS_KEY in object_version["Metadata"]:
      self._status = object_version["Metadata"][EFConfig.S3_VERSION_STATUS_KEY]
    else:
      self._status = ""
    self._value = object_version["Body"].read()
    self._version_id = object_version["VersionId"]

  def __str__(self):
    return "{} {} {} {} {} {} {} {}".format(self._value, self._build_number, self._commit_hash, self._last_modified,
                                            self._modified_by, self._version_id, self._location, self._status)

  def __repr__(self):
    return str(self.to_json())

  def to_json(self):
    """
    called by VersionEncoder.default() when doing json.dumps() on the object
    the json materializes in reverse order from the order used here
    """
    return {
        "build_number": self._build_number,
        "commit_hash": self._commit_hash,
        "last_modified": self._last_modified,
        "location": self._location,
        "modified_by": self._modified_by,
        "status": self._status,
        "value": self._value,
        "version_id": self._version_id
    }

  @property
  def build_number(self):
    return self._build_number

  @property
  def commit_hash(self):
    return self._commit_hash

  @property
  def last_modified(self):
    return self._last_modified

  @property
  def location(self):
    return self._location

  @property
  def modified_by(self):
    return self._modified_by

  @property
  def status(self):
    return self._status

  @property
  def value(self):
    return self._value


class VersionEncoder(json.JSONEncoder):
  """
  provide a json encoder for the Version class to support json.dumps() output
  """

  def default(self, obj):
    if isinstance(obj, Version):
      return obj.to_json()
    return json.JSONEncoder.default(self, obj)


# Utilities
def handle_args_and_set_context(args):
  """
  Args:
    args: the command line args, probably passed from main() as sys.argv[1:]
  Returns:
    a populated EFVersionContext object
  """
  parser = argparse.ArgumentParser()
  parser.add_argument("service_name", help="name of the service")
  parser.add_argument("key", help="version key to look up for <service_name> such as 'ami-id' (list in EF_Config)")
  parser.add_argument("env", help=", ".join(EFConfig.ENV_LIST))
  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument("--get", help="get current version", action="store_true")
  group.add_argument("--set", help="set current version of <key> to <value> for <service_name>")
  group.add_argument("--rollback", help="set current version to most recent 'stable' version in history",
                     action="store_true")
  group.add_argument("--history", help="Show version history for env/service/key", choices=['json', 'text'])
  group.add_argument("--show", help="Show keys and values. '*' allowed for <key> and <env>",
                     action="store_true", default=False)
  parser.add_argument("--build",
                      help="On --set, also set the externally defined build number associated with the version entity",
                      default="")
  parser.add_argument("--commit_hash", help="On --set, also set the commit hash associated with the version entity",
                      default="")
  parser.add_argument("--commit", help="Actually --set or --rollback (dry run if omitted)",
                      action="store_true", default=False)
  parser.add_argument("--devel", help="Allow running from branch; don't refresh from origin", action="store_true",
                      default=False)
  parser.add_argument("--force_env_full", help="Override env with env_full for account-scoped environments",
                      action="store_true", default=False)
  parser.add_argument("--limit", help="Limit 'history', 'rollback', 'show' to first N records (default 100, max 1000)",
                      type=int, default=100)
  parser.add_argument("--location", help="On --set, also mark the url location of the static build's version file to"
                      "support dist-hash precheck", default="")
  if EFConfig.ALLOW_EF_VERSION_SKIP_PRECHECK:
    parser.add_argument("--noprecheck", help="--set or --rollback without precheck", action="store_true", default=False)
  parser.add_argument("--sr", help="optional /path/to/service_registry_file.json", default=None)
  parser.add_argument("--stable", help="On --set, also mark the version 'stable'", action="store_true")
  parser.add_argument("--verbose", help="Print additional info", action="store_true", default=False)
  # parse
  parsed_args = vars(parser.parse_args(args))
  context = EFVersionContext()
  # marshall the inherited context values
  context._build_number = parsed_args["build"]
  context._commit_hash = parsed_args["commit_hash"]
  context.commit = parsed_args["commit"]
  context.devel = parsed_args["devel"]
  context._force_env_full = parsed_args["force_env_full"]
  try:
    context.env = parsed_args["env"]
  except ValueError as e:
    fail("Error in env: {}".format(e.message))
  # marshall this module's additional context values
  context._get = parsed_args["get"]
  context._history = parsed_args["history"]
  context._key = parsed_args["key"]
  if EFConfig.ALLOW_EF_VERSION_SKIP_PRECHECK:
    context._noprecheck = parsed_args["noprecheck"]
  if not 1 <= parsed_args["limit"] <= 1000:
    fail("Error in --limit. Valid range: 1..1000")
  context._limit = parsed_args["limit"]
  context._location = parsed_args["location"]
  context._rollback = parsed_args["rollback"]
  context._service_name = parsed_args["service_name"]
  context._show = parsed_args["show"]
  context._stable = parsed_args["stable"]
  context._value = parsed_args["set"]
  # Set up service registry and policy template path which depends on it
  context.service_registry = EFServiceRegistry(parsed_args["sr"])

  # VERBOSE is global
  global VERBOSE
  VERBOSE = parsed_args["verbose"]

  validate_context(context)
  return context


def print_if_verbose(message):
  if VERBOSE:
    print(message, file=sys.stderr)


def validate_context(context):
  """
    Set the key for the current context.
    Args:
      context: a populated EFVersionContext object
  """
  # Service must exist in service registry
  if not context.service_registry.service_record(context.service_name):
    fail("service: {} not found in service registry: {}".format(
         context.service_name, context.service_registry.filespec))
  service_type = context.service_registry.service_record(context.service_name)["type"]

  # Key must be valid
  if context.key not in EFConfig.VERSION_KEYS:
    fail("invalid key: {}; see VERSION_KEYS in ef_config for supported keys".format(context.key))

  # Lookup allowed key for service type
  if "allowed_types" in EFConfig.VERSION_KEYS[context.key] and \
          service_type not in EFConfig.VERSION_KEYS[context.key]["allowed_types"]:
    fail("service_type: {} is not allowed for key {}; see VERSION_KEYS[KEY]['allowed_types']"
         "in ef_config and validate service registry entry".format(service_type, context.key))

  return True


def precheck_ami_id(context):
  """
  Is the AMI in service the same as the AMI marked current in the version records?
  This tool won't update records unless the world state is coherent.
  Args:
    context: a populated EFVersionContext object
  Returns:
    True if ok to proceed
  Raises:
    RuntimeError if not ok to proceed
  """
  # get the current AMI
  key = "{}/{}".format(context.env, context.service_name)
  print_if_verbose("precheck_ami_id with key: {}".format(key))
  current_ami = context.versionresolver.lookup("ami-id,{}".format(key))
  print_if_verbose("ami found: {}".format(current_ami))

  # If bootstrapping (this will be the first entry in the version history)
  # then we can't check it vs. running version
  if current_ami is None:
    print_if_verbose("precheck passed without check because current AMI is None")
    return True

  # Otherwise perform a consistency check
  # 1. get IDs of instances running the AMI - will find instances in all environments
  instances_running_ami = context.aws_client("ec2").describe_instances(
      Filters=[{
          'Name': 'image-id',
          'Values': [current_ami]
      }]
  )["Reservations"]
  if instances_running_ami:
    instances_running_ami = [resv["Instances"][0]["InstanceId"] for resv in instances_running_ami]
  print_if_verbose("instances running ami {}:\n{}".format(current_ami, repr(instances_running_ami)))

  # 2. Get IDs of instances running as <context.env>-<context.service_name>
  env_service = "{}-{}".format(context.env, context.service_name)
  instances_running_as_env_service = context.aws_client("ec2").describe_instances(
      Filters=[{
          'Name': 'iam-instance-profile.arn',
          'Values': ["arn:aws:iam::*:instance-profile/{}-{}".format(context.env, context.service_name)]
      }]
  )["Reservations"]
  if instances_running_as_env_service:
    instances_running_as_env_service = \
        [resv["Instances"][0]["InstanceId"] for resv in instances_running_as_env_service]
  print_if_verbose("instances running as {}".format(env_service))
  print_if_verbose(repr(instances_running_as_env_service))

  # 3. Instances running as env-service should be a subset of instances running the AMI
  for instance_id in instances_running_as_env_service:
    if instance_id not in instances_running_ami:
      raise RuntimeError("Instance: {} not running expected ami: {}".format(instance_id, current_ami))

  # Check passed - all is well
  return True


def precheck_dist_hash(context):
  """
  Is the dist in service the same as the dist marked current in the version records?
  This tool won't update records unless the world state is coherent.
  Args:
    context: a populated EFVersionContext object
  Returns:
    True if ok to proceed
  Raises:
    RuntimeError if not ok to proceed
  """
  # get the current dist-hash
  key = "{}/{}/dist-hash".format(context.service_name, context.env)
  print_if_verbose("precheck_dist_hash with key: {}".format(key))
  try:
    current_dist_hash = Version(context.aws_client("s3").get_object(
        Bucket=EFConfig.S3_VERSION_BUCKET,
        Key=key
    ))
    print_if_verbose("dist-hash found: {}".format(current_dist_hash.value))
  except ClientError as error:
    if error.response["Error"]["Code"] == "NoSuchKey":
      # If bootstrapping (this will be the first entry in the version history)
      # then we can't check it vs. current version, thus we cannot get the key
      print_if_verbose("precheck passed without check because current dist-hash is None")
      return True
    else:
      fail("Exception while prechecking dist_hash for {} {}: {}".format(context.service_name, context.env, error))

  # Otherwise perform a consistency check
  # 1. get dist version in service for environment
  try:
    response = urllib2.urlopen(current_dist_hash.location, None, 5)
    if response.getcode() != 200:
      raise IOError("Non-200 response " + str(response.getcode()) + " reading " + current_dist_hash.location)
    dist_hash_in_service = response.read().strip()
  except urllib2.URLError as error:
    raise IOError("URLError in http_get_dist_version: " + repr(error))

  # 2. dist version in service should be the same as "current" dist version
  if dist_hash_in_service != current_dist_hash.value:
    raise RuntimeError("{} dist-hash in service: {} but expected dist-hash: {}"
                       .format(key, dist_hash_in_service, current_dist_hash.value))

  # Check passed - all is well
  return True


def precheck(context):
  """
  calls a function named "precheck_<key>" where <key> is context_key with '-' changed to '_'
  (e.g. "precheck_ami_id")
  Checking function should return True if OK, or raise RuntimeError w/ message if not
  Args:
    context: a populated EFVersionContext object
  Returns:
    True if the precheck passed, or if there was no precheck function for context.key
  Raises:
    RuntimeError if precheck failed, with explanatory message
  """
  if context.noprecheck:
    return True
  func_name = "precheck_" + context.key.replace("-", "_")
  if func_name in globals() and isfunction(globals()[func_name]):
    return globals()[func_name](context)
  else:
    return True


def get_versions(context, return_stable=False):
  """
  Get all versions of a key
  Args:
    context: a populated EFVersionContext object
    return_stable: (default:False) If True, stop fetching if 'stable' version is found; return only that version
  Returns:
    json list of object data sorted in reverse by last_modified (newest version is first). Each item is a dict:
    {
      'value': <value>,
      'last_modified": <YYYY-MM-DDThh:mm:ssZ>, (ISO8601 date time string)
      'modified_by': '<arn:aws:...>',
      'version_id': '<version_id>',
      'status': See EF_Config.S3_VERSION_STATUS_* for possible values
    }
  """
  s3_key = "{}/{}/{}".format(context.service_name, context.env, context.key)
  object_version_list = context.aws_client("s3").list_object_versions(
      Bucket=EFConfig.S3_VERSION_BUCKET,
      Delimiter='/',
      MaxKeys=context.limit,
      Prefix=s3_key
  )
  if "Versions" not in object_version_list:
    return []
  object_versions = []
  for version in object_version_list["Versions"]:
    object_version = Version(context.aws_client("s3").get_object(
        Bucket=EFConfig.S3_VERSION_BUCKET,
        Key=s3_key,
        VersionId=version["VersionId"]
    ))
    # Stop if a stable version was found and return_stable was set
    if return_stable and object_version.status == EFConfig.S3_VERSION_STATUS_STABLE:
      return [object_version]
    object_versions.append(object_version)

  # If caller is looking for a 'stable' version and we made it to here, a stable version was not found
  if return_stable:
    return []
  else:
    return sorted(object_versions, key=lambda v: v.last_modified, reverse=True)


def cmd_get(context):
  obj_value = context.versionresolver.lookup("{},{}/{}".format(context.key, context.env, context.service_name))
  print(obj_value)


def cmd_history(context):
  versions = get_versions(context)
  if context.history == "text":
    print("{}-{} {}".format(context.env, context.service_name, context.key))
    for v in versions:
      print(v)
  elif context.history == "json":
    print(json.dumps(versions, cls=VersionEncoder))


def cmd_rollback(context):
  """
  Roll back by finding the most recent "stable" tagged version, and putting it again, so that
  it's the new "current" version.
  Args:
    context: a populated EFVersionContext object
  """
  last_stable = get_versions(context, return_stable=True)
  if len(last_stable) != 1:
    fail("Didn't find a version marked stable for key: {} in env/service: {}/{}".format(
         context.key, context.env, context.service_name))
  context.value = last_stable[0].value
  context.commit_hash = last_stable[0].commit_hash
  context.build_number = last_stable[0].build_number
  context.location = last_stable[0].location
  context.stable = True
  cmd_set(context)


def _getlatest_ami_id(context):
  """
  Get the most recent AMI ID for a service
  Args:
    context: a populated EFVersionContext object
  Returns:
    ImageId or None if no images exist or on error
  """
  try:
    response = context.aws_client("ec2").describe_images(
        Filters=[
            {"Name": "is-public", "Values": ["false"]},
            {"Name": "name", "Values": [context.service_name + EFConfig.AMI_SUFFIX + "*"]}
        ])
  except:
    return None
  if len(response["Images"]) > 0:
    return sorted(response["Images"], key=itemgetter('CreationDate'), reverse=True)[0]["ImageId"]
  else:
    return None


def cmd_set(context):
  """
  Set the new "current" value for a key.
  If the existing current version and the new version have identical /value/ and /status,
   then nothing is written, to avoid stacking up redundant entreis in the version table.
  Args:
    context: a populated EFVersionContext object
  """
  # If key value is a special symbol, see if this env allows it
  if context.value in EFConfig.SPECIAL_VERSIONS and context.env_short not in EFConfig.SPECIAL_VERSION_ENVS:
    fail("special version: {} not allowed in env: {}".format(context.value, context.env_short))
  # If key value is a special symbol, the record cannot be marked "stable"
  if context.value in EFConfig.SPECIAL_VERSIONS and context.stable:
    fail("special versions such as: {} cannot be marked 'stable'".format(context.value))

  # Resolve any references
  if context.value == "=prod":
    context.value = context.versionresolver.lookup("{},{}/{}".format(context.key, "prod", context.service_name))
  elif context.value == "=staging":
    context.value = context.versionresolver.lookup("{},{}/{}".format(context.key, "staging", context.service_name))
  elif context.value == "=latest":
    if not EFConfig.VERSION_KEYS[context.key]["allow_latest"]:
      fail("=latest cannot be used with key: {}".format(context.key))
    func_name = "_getlatest_" + context.key.replace("-", "_")
    if func_name in globals() and isfunction(globals()[func_name]):
      context.value = globals()[func_name](context)
    else:
      raise RuntimeError("{} version for {}/{} is '=latest' but can't look up because method not found: {}".format(
                         context.key, context.env, context.service_name, func_name))

  # precheck to confirm coherent world state before attempting set - whatever that means for the current key type
  try:
    precheck(context)
  except Exception as e:
    fail("Precheck failed: {}".format(e.message))

  s3_key = "{}/{}/{}".format(context.service_name, context.env, context.key)
  s3_version_status = EFConfig.S3_VERSION_STATUS_STABLE if context.stable else EFConfig.S3_VERSION_STATUS_UNDEFINED

  # If the set would put a value and status that are the same as the existing 'current' value/status, don't do it
  context.limit = 1
  current_version = get_versions(context)
  # If there is no 'current version' it's ok, just means the set will write the first entry
  if len(current_version) == 1 and current_version[0].status == s3_version_status and \
          current_version[0].value == context.value:
      print("Version not written because current version and new version have identical value and status: {} {}"
            .format(current_version[0].value, current_version[0].status))
      return

  if not context.commit:
    print("=== DRY RUN ===\nUse --commit to set value\n=== DRY RUN ===")
    print("would set key: {} with value: {} {} {} {} {}".format(
          s3_key, context.value, context.build_number, context.commit_hash, context.location, s3_version_status))
  else:
    context.aws_client("s3").put_object(
        ACL='bucket-owner-full-control',
        Body=context.value,
        Bucket=EFConfig.S3_VERSION_BUCKET,
        ContentEncoding=EFConfig.S3_VERSION_CONTENT_ENCODING,
        Key=s3_key,
        Metadata={
            EFConfig.S3_VERSION_BUILDNUMBER_KEY: context.build_number,
            EFConfig.S3_VERSION_COMMITHASH_KEY: context.commit_hash,
            EFConfig.S3_VERSION_LOCATION_KEY: context.location,
            EFConfig.S3_VERSION_MODIFIEDBY_KEY: context.aws_client("sts").get_caller_identity()["Arn"],
            EFConfig.S3_VERSION_STATUS_KEY: s3_version_status
        },
        StorageClass='STANDARD'
    )
    print("set key: {} with value: {} {} {} {} {}".format(
          s3_key, context.value, context.build_number, context.commit_hash, context.location, s3_version_status))


def cmd_show(context):
  print("cmd_show is not implemented")


def main():
  # Fetch args and load context
  context = handle_args_and_set_context(sys.argv[1:])

  # Refresh from repo if necessary and possible (gets don't need service registry, sets do)
  if (context.rollback or context.value) and not (context.devel or getenv("JENKINS_URL", False)):
    print("Refreshing repo")
    try:
      pull_repo()
    except RuntimeError as error:
      fail("Error checking or pulling repo", error)

  # Sign on to AWS and create clients
  if context.whereami in ["ec2"]:
    # Always use instance credentials in EC2. One day we'll have "lambda" in there too, so use "in" w/ list
    aws_session_alias = None
  else:
    # Otherwise use local user credential matching the account alias
    aws_session_alias = context.account_alias
  # Make AWS clients
  try:
    context.set_aws_clients(create_aws_clients(EFConfig.DEFAULT_REGION, aws_session_alias, "ec2", "s3", "sts"))
  except RuntimeError:
    fail("Exception creating AWS client in region {} with aws account alias {} (None=instance credentials)".format(
         EFConfig.DEFAULT_REGION, aws_session_alias))

  # Instantiate a versionresolver - we'll use some of its methods
  context._versionresolver = EFVersionResolver(context.aws_client())

  # Carry out the requested action
  if context.get:
    cmd_get(context)
  elif context.history:
    cmd_history(context)
  elif context.rollback:
    cmd_rollback(context)
  elif context.show:
    cmd_show(context)
  elif context.value:
    cmd_set(context)


if __name__ == "__main__":
  main()
