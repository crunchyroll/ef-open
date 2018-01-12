#!/usr/bin/env python

from __future__ import print_function
import argparse
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
    self._length = 32
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
    ef_utils.fail("Error in env: {}".format(e.message))
  context.service = parsed_args["service"]
  context.decrypt = parsed_args["decrypt"]
  context.length = parsed_args["length"]
  context.plaintext = parsed_args["plaintext"]
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

  if context.decrypt:
    decrypted_password = ef_utils.kms_decrypt(kms_client=clients['kms'], secret=context.decrypt)
    print("Decrypted Secret: {}".format(decrypted_password))
    return

  if context.plaintext:
    password = context.plaintext
  else:
    password = generate_secret(context.length)
    print("Generated Secret: {}".format(password))
  encrypted_password = ef_utils.kms_encrypt(clients['kms'], context.service, context.env, password)
  print("{{aws:kms:decrypt,%s}}" % encrypted_password)
  return


if __name__ == "__main__":
  main()
