import base64
import json
from collections import OrderedDict
import re
import os
import hashlib
import sqlite3

import boto3
import botocore.exceptions

from ef_utils import fail
from ef_site_config import EFSiteConfig

class LockConfig(object):
    configdir = './configs/cr-web'
    parameter_exten = '.parameters.json'
    encrypted_start_char = '_'
    lockfile_dir = '.ef-lock/locked'

    def __init__(self):
        self.db_file = os.path.join(os.getcwd(), '.ef-lock/objects.db')


class ObjectDb(object):
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()


def kms_encrypt(kms_client, service, env, secret):
    """
    Encrypt string for use by a given service/environment
    Args:
      kms_client (boto3 kms client object): Instantiated kms client object. Usually created through create_aws_clients.
      service (string): name of the service that the secret is being encrypted for.
      env (string): environment that the secret is being encrypted for.
      secret (string): value to be encrypted
    Returns:
      a populated EFPWContext object
    Raises:
      SystemExit(1): If there is an error with the boto3 encryption call (ex. missing kms key)
    """
    # Converting all periods to underscores because they are invalid in KMS alias names
    key_alias = '{}-{}'.format(env, service.replace('.', '_'))

    try:
        response = kms_client.encrypt(
            KeyId='alias/{}'.format(key_alias),
            Plaintext=secret.encode()
        )
    except ClientError as error:
        if error.response['Error']['Code'] == "NotFoundException":
            fail("Key '{}' not found. You may need to run ef-generate for this environment.".format(key_alias), error)
        else:
            fail("boto3 exception occurred while performing kms encrypt operation.", error)
    encrypted_secret = base64.b64encode(response['CiphertextBlob'])
    return encrypted_secret


def kms_decrypt(kms_client, secret):
    """
    Decrypt kms-encrypted string
    Args:
      kms_client (boto3 kms client object): Instantiated kms client object. Usually created through create_aws_clients.
      secret (string): base64 encoded value to be decrypted
    Returns:
      a populated EFPWContext object
    Raises:
      SystemExit(1): If there is an error with the boto3 decryption call (ex. malformed secret)
    """
    try:
        decrypted_secret = kms_client.decrypt(CiphertextBlob=base64.b64decode(secret))['Plaintext']
    except TypeError:
        fail("Malformed base64 string data")
    except ClientError as error:
        if error.response["Error"]["Code"] == "InvalidCiphertextException":
            fail("The decrypt request was rejected because the specified ciphertext \
      has been corrupted or is otherwise invalid.", error)
        elif error.response["Error"]["Code"] == "NotFoundException":
            fail("The decrypt request was rejected because the specified entity or resource could not be found.", error)
        else:
            fail("boto3 exception occurred while performing kms decrypt operation.", error)
    return decrypted_secret


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


def get_md5sum(filepath):
    with open(filepath) as f:
        data = f.read()
    return hashlib.md5(data).hexdigest()


def hash_string(string_input):
    return hashlib.md5(string_input).hexdigest()


def decrypt_file(file_path, clients, encryption_char=LockConfig.encrypted_start_char):
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
                    decrypted_value = kms_decrypt(clients[env], encrypted_value)
                    data['params'][env][key] = decrypted_value
                    changed = True
                    # try:
                    #     decrypted_value = kms_decrypt(clients[env], encrypted_value)
                    #     data['params'][env][key] = decrypted_value
                    #     changed = True
                    # except: # TODO: Find botocore exception for missing permissions
                    #     pass
    if changed:
        with open(file_path, "w") as encrypted_file:
            json.dump(data, encrypted_file, indent=2, separators=(',', ': '))
            # Writing new line here so it conforms to WG14 N1256 5.1.1.1 (so github doesn't complain)
            encrypted_file.write("\n")


def is_repo_unlocked():
    try:
        os.stat(LockConfig.db_file)
        return True
    except OSError:
        return False


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