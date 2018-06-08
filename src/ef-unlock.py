import os.path
import re
import sqlite3
import hashlib
import shutil
import json
from collections import OrderedDict
import boto3
import botocore.exceptions

from ef_site_config import EFSiteConfig
from ef_utils import kms_decrypt

topdir = './configs'

# The arg argument for walk, and subsequently ext for step
exten = '.parameters.json'

service = re.compile('\./configs/(.+)/parameters')
encrypted_start_char = '_'

files = []

def step(ext, dirname, names):
    ext = ext.lower()

    for name in names:
        if name.lower().endswith(ext):
            files.append({
                "service": service.match(dirname).group(1),
                "params_dir": dirname,
                "filepath": os.path.join(dirname, name),
                "filename": name
            })
            filepath = os.path.join(dirname, name)

            # Make copy named .filename.locked
            # This will be restored when ef-lock is called as long as no changes have taken place on this file
            locked_copy = ".{}.locked".format(name)
            locked_copy_filepath = os.path.join(dirname, locked_copy)
            shutil.copy2(filepath, locked_copy_filepath)

            # Unencrypt file


def create_kms_clients():
    """
    Create KMS client for each account in the site_config with a matching profile in ~/.aws/config
    :return: Dict containing map of environments to kms client. Key = env, Value = ref to relevant kms client
    """
    kms = {}
    site_config = EFSiteConfig().load
    account_map = site_config['ENV_ACCOUNT_MAP']
    region = site_config['DEFAULT_REGION']  # TODO: create optional runtime param to override this
    ephemeral_envs = site_config['EPHEMERAL_ENVS']
    account_names = set(account_map.values())
    for alias in account_names:
        try:
            session = boto3.session.Session(profile_name=alias, region_name=region)
            client = session.client('kms')
            for env, account in account_map.items():
                if account == alias:
                    if env in ephemeral_envs.keys():
                        for i in range(ephemeral_envs[env]):
                            kms[env + str(i)] = client
                    else:
                        kms[env] = client
        except botocore.exceptions.ProfileNotFound:
            pass
    return kms


def is_encrypted(param_value):
    if param_value.startswith("{{aws:kms:decrypt"):
        return True
    else:
        return False

def decrypt_secret_file(file_path, clients):
  """
  Generate a parameter files with it's secrets encrypted in KMS
  Args:
      file_path (string): Path to the parameter file to be encrypted
      pattern (string): Pattern to do fuzzy string matching
      service (string): Service to use KMS key to encrypt file
      clients (dict): KMS AWS client that has been instantiated
  Returns:
      None
  Raises:
    IOError: If the file does not exist
  """
  with open(file_path) as json_file:
    data = json.load(json_file, object_pairs_hook=OrderedDict)
  for env, params in data["params"].items():
      if env in clients.keys():
          for key, value in params.items():
              if key.startswith('_') and is_encrypted(value):
                  print()

    # if pattern in key:
    #   if "aws:kms:decrypt" in value:
    #     print("Found match, key {} but value is encrypted already; skipping...".format(key))
    #   else:
    #     print("Found match, encrypting key {}".format(key))
    #     encrypted_password = ef_utils.kms_encrypt(clients['kms'], service, environment, value)
    #     data["params"][environment][key] = format_secret(encrypted_password)
    #     changed = True


test_file = 'configs/cr-web/parameters/config_prod.yml.parameters.json'
kms = create_kms_clients()
decrypt_secret_file(test_file, kms)


# Start the walk
# os.path.walk(topdir, step, exten)

# Store MD5Sum of all unencrypted files in sqlite

# Add configs/ to .gitignore

# TODO: Validation to make sure ef-unlock isn't run twice in a row

# TODO: Handling for if a user has a profile matching the account, but is missing decrypt permissions

# with open(os.path.join(dirname, name)) as f:
#     data = f.read()
#     print(hashlib.md5(data).hexdigest())

# Ef-lock should be able to to run either after ef-unlock (where it cleans everything up) or on its own
