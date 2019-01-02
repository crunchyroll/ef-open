"""
Copyright 2016-2018 Ellation, Inc.

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

from __future__ import absolute_import, division, print_function

import json
import logging
import os
import os.path
import re
import subprocess
import sys
import time

import click
from botocore.exceptions import ClientError

from .ef_config import EFConfig
from .ef_service_registry import EFServiceRegistry
from .ef_utils import create_aws_clients, get_account_alias, whereami

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stderr)
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
logger.addHandler(ch)

logging.getLogger('botocore').setLevel(logging.CRITICAL)

ret_code = 0
service_registry = None


def changeset_is_empty(response):
    return (response['Status'] == 'FAILED' and "didn't contain changes" in response['StatusReason'])


def wait_for_changeset_creation(cf_client, changeset_id, changeset_stackid):
    remaining_tries = 30
    while remaining_tries > 0:
        remaining_tries -= 1
        res = cf_client.describe_change_set(ChangeSetName=changeset_id, StackName=changeset_stackid)
        if res['Status'] in ['CREATE_PENDING', 'CREATE_IN_PROGRESS']:
            time.sleep(10)
            continue
        return
    raise Exception('Timed out waiting for changeset to create.')


def generate_changeset(service_name, environment, repo_root, template_file):
    """
    Given a service name and environment, and the details of where the
    template file is, call ef-cf to generate a changeset.  Return the json
    description response that's printed in the ef-cf output.

    Will throw Exception if something goes wrong with the ef-cf call.
    """
    cmd = 'cd {} && ef-cf {} {} --changeset --devel'.format(repo_root, template_file, environment)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    if p.returncode != 0:
        stderr = '\n{}'.format(stderr).replace('\n', '\n        ')
        stdout = '\n{}'.format(stdout).replace('\n', '\n        ')
        raise Exception('Service: `{}`, Env: `{}`, Msg: `{}{}`'
                        .format(service_name, environment, stderr, stdout))

    logger.debug('Created changeset for `%s` in `%s`', template_file, environment)

    r = re.match(r".*^Changeset Info: (.*)$", stdout, re.MULTILINE | re.DOTALL)
    return json.loads(r.group(1))


def delete_any_existing_changesets(cf_client, service_name, environment):
    stack_name = '{}-{}'.format(environment, service_name)
    logger.debug('Deleting existing changesets for `%s`', stack_name)

    try:
        changesets = cf_client.list_change_sets(StackName=stack_name)
    except ClientError as e:
        logger.debug("Error listing existing changesets: %s", e)
        return

    for changeset in changesets['Summaries']:
        logger.debug('Deleting existing changeset: `%s`', changeset['ChangeSetId'])
        cf_client.delete_change_set(ChangeSetName=changeset['ChangeSetId'], StackName=changeset['StackId'])


def get_cloudformation_client(service_name, environment_name):
    """
    Given a service name and an environment name, return a boto CloudFormation
    client object.
    """
    region = service_registry.service_region(service_name)

    if whereami() == 'ec2':
        profile = None
    else:
        profile = get_account_alias(environment_name)

    clients = create_aws_clients(region, profile, 'cloudformation')
    return clients['cloudformation']


def generate_test_environment_name(env_name):
    """
    Some environments, like proto, need a numerical index, while others, like
    prod do not.  Given an environment name from the service registry, return a
    valid environment name in which to generate a template.
    """
    if env_name in ['alpha', 'proto']:
        return '{}0'.format(env_name)
    return env_name


def get_env_categories(envs):
    """
    Given a list of environments, return an associated list of environment
    base names where, for example, 'proto0' becomes 'proto', but 'staging'
    remains 'staging'.
    """
    return [re.match(r'^(.*?)\d*$', name).group(1) for name in envs]


def evaluate_changesets(services, repo_root, include_env):
    """
    Given a dict of services, use ef-cf to render the cloudformation
    templates and then generate changesets for each one.
    These can then be evaluated for emptiness in a later step.

    Sub-services (names with '.' in them) are skipped.

    If an ef-cf call fails, the error will be logged, the retcode set to 2, but
    the function will run to completion and return the list of non-error
    results.
    """
    global ret_code

    for service_name, service in services.iteritems():

        for env_category in service['environments']:
            if env_category not in get_env_categories(include_env):
                logger.debug('Skipping not-included environment `%s` for service `%s`',
                             env_category, service_name)
                continue

            environment = generate_test_environment_name(env_category)

            cf_client = get_cloudformation_client(service_name, environment)

            delete_any_existing_changesets(cf_client, service_name, environment)

            try:
                changeset = generate_changeset(service_name, environment,
                                               repo_root, service['template_file'])
            except Exception as e:
                ret_code = 2
                logger.error(e)
                continue

            logger.info('Investigating changeset for service `%s` '
                        'in environment `%s`\n       Changeset ID: `%s`',
                        service_name, environment, changeset['Id'])

            wait_for_changeset_creation(cf_client, changeset['Id'], changeset['StackId'])

            desc = cf_client.describe_change_set(
                ChangeSetName=changeset['Id'], StackName=changeset['StackId'])

            cf_client.delete_change_set(
                ChangeSetName=changeset['Id'], StackName=changeset['StackId'])

            if changeset_is_empty(desc):
                logger.info('Deployed service `%s` in environment `%s` matches '
                            'the local template.', service_name, environment)
            else:
                ret_code = 1
                logger.error('Service `%s` in environment `%s` differs from '
                             'the local template.',
                             service_name, environment)
                details = json.dumps(desc['Changes'], indent=2, sort_keys=True).replace('\n', '\n        ')
                logger.info('Change details: %s', details)


def test_for_unused_template_files(template_files, services):
    """
    Loop over the template files, and print a warning for any that aren't
    used by a service in the service registry
    (the annoying sub-function is to deal with Python's lack of a labeled break)
    """
    def print_unused_template_warning(file, services):
        for service_name, service in services.iteritems():
            if service['template_file'] == file:
                return
        logger.warning("Template file has no service registry entry: `%s`", file)

    for name, file in template_files.iteritems():
        print_unused_template_warning(file, services)


def get_matching_service_template_file(service_name, template_files):
    """
    Return the template file that goes with the given service name, or return
    None if there's no match.  Subservices return the parent service's file.
    """
    # If this is a subservice, use the parent service's template
    service_name = service_name.split('.')[0]
    if service_name in template_files:
        return template_files[service_name]
    return None


def get_dict_registry_services(registry, template_files, warn_missing_files=True):
    """
    Return a dict mapping service name to a dict containing the service's
    type ('fixtures', 'platform_services', 'application_services', 'internal_services'),
    the template file's absolute path, and a list of environments to which the
    service is intended to deploy.

    Service names that appear twice in the output list will emit a warning and
    ignore the latter records.

    Services which have no template file will not appear in the returned dict.
    If the `warn_missing_files` boolean is True these files will emit a warning.
    """
    with open(registry) as fr:
        parsed_registry = json.load(fr)

    services = {}
    for type in ['fixtures', 'platform_services', 'application_services', 'internal_services']:
        for name, service in parsed_registry[type].iteritems():
            if name in services:
                logger.warning("Template name appears twice, ignoring later items: `%s`", name)
                continue

            template_file = get_matching_service_template_file(name, template_files)
            if not template_file:
                if warn_missing_files:
                    logger.warning("No template file for `%s` (%s) `%s`", type, service['type'], name)
                continue

            services[name] = {
                'type': type,
                'template_file': template_file,
                'environments': service['environments']
            }

    return services


def scan_dir_for_template_files(search_dir):
    """
    Return a map of "likely service/template name" to "template file".
    This includes all the template files in fixtures and in services.
    """
    template_files = {}
    for type in ['fixtures', 'services']:
        for x in os.listdir(os.path.join(search_dir, 'cloudformation', type, 'templates')):
            name = os.path.splitext(x)[0]
            template_files[name] = os.path.join(search_dir, 'cloudformation', type, 'templates', x)
    return template_files


@click.command()
@click.option('--repo_root',
              default="./",
              required=False,
              type=click.Path(exists=True, file_okay=False, dir_okay=True,
                              readable=True, resolve_path=True),
              help="The root directory of the template repository git clone.")
@click.option('--sr',
              default=None,
              required=False,
              type=click.Path(exists=True, file_okay=True, dir_okay=False,
                              readable=True, resolve_path=True),
              help="optional /path/to/service_registry_file.json")
@click.option('--env', '-e',
              multiple=True,
              required=True,
              type=click.Choice(EFConfig.ENV_LIST),
              help="An environment to evaluate. Can be set several times.")
@click.option('--template_file', '-t',
              multiple=True,
              required=False,
              type=click.Path(exists=True, file_okay=True, dir_okay=False,
                              readable=True, resolve_path=True),
              help="A specific template to process.  Can be passed multiple "
                   "times.  If excluded, all templates will be run.")
@click.version_option()
def main(repo_root, sr, env, template_file):
    global service_registry
    service_registry = EFServiceRegistry(sr)

    template_files = scan_dir_for_template_files(repo_root)

    # If the list of whitelisted templates was passed, we're in "only test
    # those templates" mode.  Otherwise we'll just do every template.
    if template_file:
        template_files = {name: file
                          for name, file in template_files.iteritems()
                          if file in template_file}

    services = get_dict_registry_services(service_registry.filespec,
                                          template_files,
                                          warn_missing_files=(not template_file))

    test_for_unused_template_files(template_files, services)

    evaluate_changesets(services, repo_root, env)

    exit(ret_code)
