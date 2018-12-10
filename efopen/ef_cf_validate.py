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

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stderr)
ch.setLevel(logging.DEBUG)
ch.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
logger.addHandler(ch)

ret_code = 0


def call_cfn_validate(file):
    """
    Evaluate the cfn-validate command, for the given file, and dump the output in the
    given subdirectory.  Make the output directory if it doesn't exist.
    """
    logger.debug("Validating: `%s`", file)

    cmd = 'cfn-lint {}'.format(file)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        global ret_code
        ret_code = 1
    return stdout


def validate_cloud_formation_templates(template_dir, output_dir, print_val_out=False):
    """
    Loop over all the generated templates in the given temporary directory,
    and evaluate each template for correctness.
    """
    envdirs = os.listdir(template_dir)
    for envdir in envdirs:
        envdir_fullpath = os.path.join(template_dir, envdir)
        template_files = os.listdir(envdir_fullpath)

        for template_file in template_files:
            template_file = os.path.join(envdir_fullpath, template_file)

            val_output = call_cfn_validate(template_file)

            if print_val_out:
                print(val_output)

            if output_dir:
                env_output_dir = os.path.join(output_dir, envdir)
                try:
                    os.mkdir(output_dir)
                except OSError:
                    pass

                try:
                    os.mkdir(env_output_dir)
                except OSError:
                    pass

                template_file_ext = os.path.splitext(os.path.basename(template_file))[0]
                with open(os.path.join(env_output_dir, template_file_ext), 'w') as f:
                    f.write(val_output)


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


def render_templates(services, ef_root, target_dir, exclude_env, print_template=False):
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
            if environment in exclude_env:
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

                if print_template:
                    print(tpl_content)

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


def get_matching_service_template_file(name, template_files):
    """
    Return the template file that goes with the given service name, or return
    None if there's no match.  Subservices return the parent service's file.
    """
    # If this is a subservice, use the parent service's template
    name = name.split('.')[0]
    if name in template_files:
        return template_files[name]
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


def get_all_template_files(search_dir):
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
              required=True,
              type=click.Path(exists=True, file_okay=False, dir_okay=True,
                              readable=True, resolve_path=True),
              help="The root directory of the ellation_formation git clone.")
@click.option('--registry',
              default=None,
              required=False,
              type=click.Path(exists=True, file_okay=True, dir_okay=False,
                              readable=True, resolve_path=True),
              help="The service registry file.  If absent, we'll assume the "
                   "registry is in the ef_root directory.")
@click.option('--output_dir', '-o',
              default=None,
              required=False,
              type=click.Path(exists=False, file_okay=False, dir_okay=True,
                              writable=True, resolve_path=True),
              help="The root directory in which to generate the log output.")
@click.option('--exclude_env', '-e',
              multiple=True,
              required=False,
              type=click.Choice(['alpha', 'internal', 'prod', 'proto', 'staging']),
              help="An environment to skip. Can be set several times.")
@click.option('--include_template', '-t',
              multiple=True,
              required=False,
              type=click.Path(exists=True, file_okay=True, dir_okay=False,
                              readable=True, resolve_path=True),
              help="A specific template to process.  Can be passed multiple times.  "
                   "If excluded, all templates will be run.")
@click.option('--print_val_out', '-p',
              is_flag=True,
              help="Should we print the template validation output?")
@click.option('--print_template', '-r',
              is_flag=True,
              help="Should we print the evaluated template?")
def main(ef_root, registry, output_dir, exclude_env, include_template, print_val_out, print_template):
    if not registry:
        registry = os.path.join(ef_root, 'service_registry.json')

    template_files = get_all_template_files(ef_root)

    # If the list of whitelisted templates was passed, we're in "only render
    # and test those templates" mode.  Otherwise we'll just do every template.
    if include_template:
        template_files = {name: file
                          for name, file in template_files.iteritems()
                          if file in include_template}

    services = get_dict_registry_services(registry, template_files,
                                          warn_missing_files=(not include_template))

    test_for_unused_template_files(template_files, services)

    template_gendir = tempfile.mkdtemp()

    render_templates(services, ef_root, template_gendir, exclude_env, print_template)

    validate_cloud_formation_templates(template_gendir, output_dir, print_val_out)

    shutil.rmtree(template_gendir)

    exit(ret_code)
