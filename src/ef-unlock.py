import os.path
import re
import hashlib
import shutil
import json
from collections import OrderedDict
import sqlite3
import sys

import boto3
import botocore.exceptions

from ef_site_config import EFSiteConfig
from ef_utils import kms_decrypt


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


def decrypt_file(file_path, clients, encryption_char='_'):
    """
    Generate a parameter files with it's secrets encrypted in KMS
    Args:
        file_path (string): Path to the parameter file to be encrypted
        clients (dict): KMS AWS client that has been instantiated
        encryption_char (string): The symbol/text preceding encypted values
    Returns:
        None
    Raises:
      IOError: If the file does not exist
    """
    changed = False
    with open(file_path) as json_file:
        data = json.load(json_file, object_pairs_hook=OrderedDict)
    for env, params in data["params"].items():
        if env in clients.keys():
            for key, value in params.items():
                if key.startswith(encryption_char) and value.startswith("{{aws:kms:decrypt"):
                    encrypted_value = "".join(value.strip('{}').split(',')[1:])  # strip away ef-open lookup symbols
                    try:
                        decrypted_value = kms_decrypt(clients[env], encrypted_value)
                        data['params'][env][key] = decrypted_value
                        changed = True
                    except: # TODO: Find botocore exception for missing permissions
                        pass
    if changed:
        with open(file_path, "w") as encrypted_file:
            json.dump(data, encrypted_file, indent=2, separators=(',', ': '))
            # Writing new line here so it conforms to WG14 N1256 5.1.1.1 (so github doesn't complain)
            encrypted_file.write("\n")


def file_as_bytes(file):
    with file:
        return file.read()


def find_param_files(configdir, parameter_exten):
    service = re.compile('\./configs/(.+)/parameters')
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

    os.path.walk(configdir, step, parameter_exten)
    return files


def create_locked_copy(filename, parent_dir):
    source_filepath = os.path.join(parent_dir, filename)
    locked_copy = ".{}.locked".format(filename)
    locked_copy_filepath = os.path.join(parent_dir, locked_copy)
    shutil.copy2(source_filepath, locked_copy_filepath)


def get_md5sum(filepath):
    with open(filepath) as f:
        data = f.read()
    return hashlib.md5(data).hexdigest()


def print_if_verbose(message):
    if verbose:
        print(message)


def main():

    configdir = './configs/cr-web'
    parameter_exten = '.parameters.json'
    encrypted_start_char = '_'
    verbose = True

    # TODO: Colorize these
    if not os.path.isfile('ef_site_config.yml'):
        print("ef-unlock must be run at the root of the repo. exiting.")
        sys.exit(1)

    if os.path.isfile('.ef-lock'):
        print("ef-unlock has already been executed on this repo. lock with ef-lock before trying again.")
        sys.exit(1)

    # Create checksums db
    conn = sqlite3.connect('.ef-lock')
    c = conn.cursor()
    c.execute('''CREATE TABLE checksums
                 (FilePath text NOT NULL, MD5 text NOT NULL, PRIMARY KEY (FilePath))''')


    # Create kms clients for each account
    kms_clients = create_kms_clients()

    # Create collection of all param files
    files = find_param_files(configdir, parameter_exten)

    for file in files:

        # Create locked copy, ef-lock will restore this file later if the content of the params file is unchanged
        create_locked_copy(file['filename'], file['params_dir'])

        # Decrypt
        decrypt_file(file['filepath'], kms_clients, encrypted_start_char)

        # Get decrypted copy checksum. This will be used by ef-lock
        checksum = get_md5sum(file['filepath'])

        # Add configs/ to .gitignore


        # Save checksums to .ef-lock
        c.execute("INSERT INTO checksums VALUES (?, ?)", (file['filepath'], checksum))
        conn.commit()

    conn.close()


if __name__ == "__main__":
    main()
