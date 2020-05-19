#!/usr/bin/env python

from __future__ import print_function
from collections import OrderedDict
import argparse
import json
import os
import string
import sys

from ef_config import EFConfig
from ef_context import EFContext
import ef_utils


class EFPWContext(EFContext):
  def __init__(self):
    super(EFPWContext, self).__init__()
    self._decrypt = None
    self._re_encrypt = None
    self._length = 32
    self._plaintext = None
    self._secret_file = None
    self._match = None

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
  def re_encrypt(self):
    """String value if the tool should re_encrypt rather than generating a new encrypted secret"""
    return self._re_encrypt

  @re_encrypt.setter
  def re_encrypt(self, value):
    if type(value) is not str:
      raise TypeError("re_encrypt value must be str")
    self._re_encrypt = value

  @property
  def length(self):
    """Integer length of the secret to be generated"""
    return self._length

  @length.setter
  def length(self, value):
    if type(value) is not int and not value.isdigit():
      raise ValueError("length value must be int")
    elif int(value) < 10:
      raise ValueError("length value must be >= 10")
    else:
      self._length = int(value)

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

  @property
  def secret_file(self):
    """String value of the user-provided secret file to be encrypted"""
    return self._secret_file

  @secret_file.setter
  def secret_file(self, value):
    if type(value) is not str:
      raise TypeError("secret_file value must be str")
    self._secret_file = value

  @property
  def match(self):
    """String value to match against in the secret file"""
    return self._match

  @match.setter
  def match(self, value):
    if type(value) is not str:
      raise TypeError("match value must be str")
    self._match = value

def format_secret(secret):
  """
  Format secret to compatible decrypt string
  Args:
    secret (string): KMS secret hash
  Returns:
    formatted ef resolvable KMS decrypt string
  Raises:
    None
  """
  return "{{aws:kms:decrypt,%s}}" % secret

def generate_secret(length=32):
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

def generate_secret_file(file_path, pattern, service, environment, clients):
  """
  Generate a parameter files with it's secrets encrypted in KMS
  Args:
      file_path (string): Path to the parameter file to be encrypted
      pattern (string): Pattern to do fuzzy string matching
      service (string): Service to use KMS key to encrypt file
      environment (string): Environment to encrypt values
      clients (dict): KMS AWS client that has been instantiated
  Returns:
      None
  Raises:
    IOError: If the file does not exist
  """
  changed = False
  with open(file_path) as json_file:
    data = json.load(json_file, object_pairs_hook=OrderedDict)
    try:
      for key, value in data["params"][environment].items():
        if pattern in key:
          if "aws:kms:decrypt" in value:
            print("Found match, key {} but value is encrypted already; skipping...".format(key))
          else:
            print("Found match, encrypting key {}".format(key))
            encrypted_password = ef_utils.kms_encrypt(clients['kms'], service, environment, value)
            data["params"][environment][key] = format_secret(encrypted_password)
            changed = True
    except KeyError:
      ef_utils.fail("Error env: {} does not exist in parameters file".format(environment))

  if changed:
    with open(file_path, "w") as encrypted_file:
      json.dump(data, encrypted_file, indent=2, separators=(',', ': '))
      # Writing new line here so it conforms to WG14 N1256 5.1.1.1 (so github doesn't complain)
      encrypted_file.write("\n")

def handle_args_and_set_context(args):
  """
  Args:
      args: the command line args, probably passed from main() as sys.argv[1:]
  Returns:
      a populated EFPWContext object
  Raises:
      RuntimeError: if branch isn't as spec'd in ef_config.EF_REPO_BRANCH
      ValueError: if a parameter is invalid
  """
  parser = argparse.ArgumentParser(description="Encrypt/decrypt template secrets.")
  parser.add_argument("service", help="name of service password is being generated for")
  parser.add_argument("env", help=", ".join(EFConfig.ENV_LIST))
  group = parser.add_mutually_exclusive_group()
  group.add_argument("--decrypt", help="encrypted string to be decrypted", default="")
  group.add_argument("--re-encrypt", help="encrypted string to be re encrypted for a new service", default="")
  group.add_argument("--plaintext", help="secret to be encrypted rather than a randomly generated one", default="")
  group.add_argument("--secret_file", help="json file containing secrets to be encrypted", default="")
  parser.add_argument("--match", help="used in conjunction with --secret_file to match against keys to be encrypted", default="")
  parser.add_argument("--length", help="length of generated password (default 32)", default=32)
  parsed_args = vars(parser.parse_args(args))
  context = EFPWContext()

  try:
    context.env = parsed_args["env"]
  except ValueError as e:
    ef_utils.fail("Error in env: {}".format(e))

  context.service = parsed_args["service"]
  context.decrypt = parsed_args["decrypt"]
  context.re_encrypt = parsed_args["re_encrypt"]
  context.length = parsed_args["length"]
  # unescape any escapes that the shell might've added; e.g: \\n becomes \n
  context.plaintext = parsed_args["plaintext"].decode("string_escape")
  context.secret_file = parsed_args["secret_file"]
  context.match = parsed_args["match"]
  if context.match or context.secret_file:
    if not context.match or not context.secret_file:
      raise ValueError("Must have both --match and --secret_file flag")

  return context


def main():
  context = handle_args_and_set_context(sys.argv[1:])
  profile = None if context.whereami == "ec2" else context.account_alias

  try:
    clients = ef_utils.create_aws_clients(EFConfig.DEFAULT_REGION, profile, "kms")
  except RuntimeError as error:
    ef_utils.fail(
      "Exception creating clients in region {} with profile {}".format(EFConfig.DEFAULT_REGION, profile),
      error
    )

  if context.secret_file:
    generate_secret_file(context.secret_file, context.match, context.service, context.env, clients)
    return

  if context.decrypt:
    decrypted = ef_utils.kms_decrypt(kms_client=clients['kms'], secret=context.decrypt)
    key_aliases = ef_utils.kms_key_alias(clients['kms'], decrypted.key_id)
    print("Decrypted Secret: {}; Key: {}".format(decrypted.plaintext, ', '.join(key_aliases)))
    return

  if context.re_encrypt:
    encrypted_password = ef_utils.kms_re_encrypt(
      kms_client=clients['kms'],
      service=context.service,
      env=context.env,
      secret=context.re_encrypt)
    print(format_secret(encrypted_password))
    return

  if context.plaintext:
    password = context.plaintext
  else:
    password = generate_secret(context.length)
    print("Generated Secret: {}".format(password))
  encrypted_password = ef_utils.kms_encrypt(clients['kms'], context.service, context.env, password)
  print(format_secret(encrypted_password))
  return

if __name__ == "__main__":
  main()
