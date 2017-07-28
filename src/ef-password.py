#!/usr/bin/env python

from __future__ import print_function
import argparse
import base64
import os
import string
import sys

from botocore.exceptions import ClientError

from ef_config import EFConfig
from ef_context import EFContext
from ef_utils import create_aws_clients, fail


class EFPWContext(EFContext):
    def __init__(self):
        super(EFPWContext, self).__init__()
        self._decrypt = None
        self._length = None
        self._plaintext = None

    @property
    def decrypt(self):
        """String value if the tool should decrypt rather than generating a new encrypted secret"""
        return self._decrypt

    @decrypt.setter
    def decrypt(self, value):
        if type(value) is not str:
            raise TypeError("decrypt value must be str")
        self._decrypt = value

    @property
    def length(self):
        """Integer length of the secret to be generated"""
        return self._length

    @length.setter
    def length(self, value):
        try:
            self._length = int(value)
        except ValueError:
            raise ValueError("length value must be int")

    @property
    def plaintext(self):
        """String value of the user-provided secret to be encrypted"""
        return self._plaintext

    @plaintext.setter
    def plaintext(self, value):
        if type(value) is not str:
            raise TypeError("plaintext value must be str")
        if sys.getsizeof(value) > 4096:
            raise ValueError("plaintext value may not be larger than 4kb")
        self._plaintext = value


def generate_secret(length):
    """
    Generate a random secret consisting of mixed-case letters and numbers
    Args:
        length (int): Length of the generated password
    Returns:
        a randomly generated secret string
    Raises:
        None
    """
    alphabet = string.ascii_letters + string.digits
    random_bytes = os.urandom(length)
    indices = [int(len(alphabet) * (ord(byte) / 256.0)) for byte in random_bytes]
    return "".join([alphabet[index] for index in indices])


def kms_encrypt(kms_client, service, env, secret):
    """
    Encrypt string for use by a given service/environment
    Args:
        kms_client (boto3 kms client object): Usually created through ef_utils.create_aws_clients.
        service (string): name of the service that the secret is being encrypted for.
        env (string): environment that the secret is being encrypted for.
        secret (string): value to be encrypted
    Returns:
        an encrypted secret string
    Raises:
        SystemExit: when providing custom output for a caught exception
    """
    try:
        response = kms_client.encrypt(
            KeyId='alias/{}-{}'.format(env, service),
            Plaintext=secret.encode()
        )
    except ClientError as error:
        if error.response['Error']['Code'] == "NotFoundException":
            fail("Key '{}-{}' not found. You may need to run ef-generate for this environment.".format(env, service), error)
        fail("boto3 exception occurred while performing encrypt operation.", error)
    encrypted_secret = base64.b64encode(response['CiphertextBlob'])
    return encrypted_secret


def kms_decrypt(kms_client, secret):
    """
    Decrypt kms-encrypted string
    Args:
        kms_client (boto3 kms client object): Usually created through ef_utils.create_aws_clients.
        secret (string): base64 encoded value to be decrypted
    Returns:
        a decrypted copy of secret string
    Raises:
        SystemExit: when providing custom output for a caught exception
    """
    try:
        decrypted_secret = kms_client.decrypt(CiphertextBlob=base64.b64decode(secret))['Plaintext']
    except TypeError:
        fail("Malformed base64 string data")
    except ClientError as error:
        if error.response["Error"]["Code"] == "InvalidCiphertextException":
            fail("The decrypt request was rejected because the specified ciphertext \
            has been corrupted or is otherwise invalid.", error)
        if error.response["Error"]["Code"] == "NotFoundException":
            fail("The decrypt request was rejected because the specified entity or resource could not be found.", error)
        fail("boto3 exception occurred while performing decrypt operation.", error)
    return decrypted_secret


def handle_args_and_set_context(args):
    """
    Args:
        args: the command line args, probably passed from main() as sys.argv[1:]
    Returns:
        a populated EFPWContext object
    Raises:
        RuntimeError: if repo or branch isn't as spec'd in ef_config.EF_REPO and ef_config.EF_REPO_BRANCH
        ValueError: if a parameter is invalid
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("service", help="name of service password is being generated for")
    parser.add_argument("env", help=", ".join(EFConfig.ENV_LIST))
    parser.add_argument("--length", help="length of generated password (default 32)", default=32)
    parser.add_argument("--decrypt", help="encrypted string to be decrypted", default="")
    parser.add_argument("--plaintext", help="secret to be encrypted rather than a randomly generated one", default="")
    parsed_args = vars(parser.parse_args(args))
    context = EFPWContext()
    try:
        context.env = parsed_args["env"]
    except ValueError as e:
        fail("Error in env: {}".format(e.message))
    context.service = parsed_args["service"]
    context.decrypt = parsed_args["decrypt"]
    context.length = parsed_args["length"]
    context.plaintext = parsed_args["plaintext"]
    return context


def main():
    context = handle_args_and_set_context(sys.argv[1:])
    profile = None if context.whereami == "ec2" else context.account_alias

    try:
        clients = create_aws_clients(EFConfig.DEFAULT_REGION, profile, "kms")
    except RuntimeError as error:
        fail("Exception creating clients in region {} with profile {}".format(EFConfig.DEFAULT_REGION, profile), error)

    if context.decrypt:
        decrypted_password = kms_decrypt(kms_client=clients['kms'], secret=context.decrypt)
        print(decrypted_password)
        return

    if context.plaintext:
        password = context.plaintext
    else:
        password = generate_secret(context.length)
        print("Generated Secret: {}".format(password))
    encrypted_password = kms_encrypt(clients['kms'], context.service, context.env, password)
    print("Encrypted Secret: {}".format(encrypted_password))
    return

if __name__ == "__main__":
    main()

