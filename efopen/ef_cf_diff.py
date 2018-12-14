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
import shutil
import subprocess
import sys
import tempfile

import click

from .ef_config import EFConfig
from .ef_service_registry import EFServiceRegistry

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stderr)
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
logger.addHandler(ch)

ret_code = 0


def test_template(file, env_name):
    """
    Evaluate the cfn-validate command, for the given file, and dump the output in the
    given subdirectory.  Make the output directory if it doesn't exist.
    """
    logger.debug("Validating: `%s` in environment `%s`", file, env_name)

    # cmd = 'cfn-lint {}'.format(file)
    # p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # stdout, stderr = p.communicate()
    # if p.returncode != 0:
    #     global ret_code
    #     ret_code = 1
    # return stdout


def test_for_cf_template_differences(template_dir):
    """
    Loop over all the generated templates in the given temporary directory,
    and evaluate each template for differences agaist the target environment.
    """
    envdirs = os.listdir(template_dir)
    for envdir in envdirs:
        envdir_fullpath = os.path.join(template_dir, envdir)
        template_files = os.listdir(envdir_fullpath)

        for template_file in template_files:
            template_file = os.path.join(envdir_fullpath, template_file)

            test_template(template_file, envdir)


def extract_template_from_efcf_output(raw_output):
    """
    The verbose output of ef-cf has some extra text before and after the
    cloudformation template output.  Find just the template, and return that.
    """
    r = re.match(r".*(^{.*^}).*$", raw_output, re.MULTILINE | re.DOTALL)
    return r.group(1)


def generate_test_environment_name(env_name):
    """
    Some environments, like proto, need a numerical index, while others, like
    prod do not.  Given an environment name from the service registry, return a
    valid environment name in which to generate a template.
    """
    if env_name in ['alpha', 'proto']:
        return '{}0'.format(env_name)
    return env_name


def render_templates(services, ef_root, target_dir, include_env):
    """
    Given a dict of services, use ef-cf to render the cloudformation
    templates.  These can then be evaluated for correctness in a later step.

    Sub-services (names with '.' in them) are skipped.
    """
    for service_name, service in services.iteritems():

        if '.' in service_name:
            logger.debug("Service `%s` is a sub-service.  Skipping.", service_name)
            continue

        for environment in service['environments']:
            if environment not in include_env:
                logger.debug('Skipping excluded environment `%s` for service `%s`',
                             environment, service_name)
                continue

            output_dir = os.path.join(target_dir, environment)
            logger.debug('Generating template for service `%s` in `%s`: `%s`',
                         service_name, environment, output_dir)

            # Set up the output directory for this service template
            try:
                os.mkdir(output_dir)
            except OSError:
                pass

            gen_env = generate_test_environment_name(environment)

            try:
                cmd = 'cd {} && ef-cf {} {} --devel --verbose'.format(
                      ef_root, service['template_file'], gen_env)

                p = subprocess.Popen(cmd, shell=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = p.communicate()
                if p.returncode != 0:
                    raise Exception("Service: `{}`, Env: `{}`, Msg: `\n{}`".format(
                                    service_name, gen_env, stderr))

                out_filename = '{}.{}'.format(
                    service_name,
                    os.path.splitext(service['template_file'])[1][1:])
                out_file = os.path.join(output_dir, out_filename)

                tpl_content = extract_template_from_efcf_output(stdout)
                with open(out_file, 'w') as f:
                    f.write(tpl_content)

            except Exception as e:
                global ret_code
                ret_code = 1
                logger.error(e)


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
@click.option('--ef_root',
              default="./",
              required=False,
              type=click.Path(exists=True, file_okay=False, dir_okay=True,
                              readable=True, resolve_path=True),
              help="The root directory of the ellation_formation git clone.")
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
              help="A specific template to process.  Can be passed multiple times.  If excluded, all templates will be run.")
@click.version_option()
def main(ef_root, sr, env, template_file):
    service_registry = EFServiceRegistry(sr)

    template_files = scan_dir_for_template_files(ef_root)

    # If the list of whitelisted templates was passed, we're in "only render
    # and test those templates" mode.  Otherwise we'll just do every template.
    if template_file:
        template_files = {name: file
                          for name, file in template_files.iteritems()
                          if file in template_file}

    services = get_dict_registry_services(service_registry.filespec, template_files,
                                          warn_missing_files=(not template_file))

    test_for_unused_template_files(template_files, services)

    template_gendir = tempfile.mkdtemp()

    render_templates(services, ef_root, template_gendir, env)

    test_for_cf_template_differences(template_gendir)

    shutil.rmtree(template_gendir)

    exit(ret_code)
