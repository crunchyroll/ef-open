from copy import deepcopy
from itertools import chain
import logging

from ef_config import EFConfig
from ef_conf_utils import get_account_alias
from ef_utils import kms_decrypt
from newrelic_interface import NewRelic, AlertPolicy


logging.basicConfig(level=logging.INFO, Force=True)
logger = logging.getLogger(__name__)


class NewRelicAlerts(object):

  def __init__(self, context, clients):
    self.config = EFConfig.PLUGINS['newrelic']
    self.ec2_conditions = self.config.get('ec2_alert_conditions', {})
    self.ecs_conditions = self.config.get('ecs_alert_conditions', {})
    self.local_alert_nrql_conditions = self.config.get('alert_nrql_conditions', {})
    self.lambda_alert_conditions = self.config.get('lambda_alert_conditions', {})
    self.local_alert_apm_conditions = self.config.get('apm_metric_alert_conditions', {})
    self.all_notification_channels = self.config.get('env_notification_map', {})
    self.opsgenie_api_key = self.config["opsgenie_api_key"]
    self.context, self.clients = context, clients

  @classmethod
  def replace_symbols(cls, condition_obj, symbols):
    def convert_string(string):
      for symbol in symbols:
        if symbol in string:
          string = string.replace("{{" + symbol + "}}", str(symbols[symbol]))
          if isinstance(symbols[symbol], int):
            string = int(string)
      return string

    if isinstance(condition_obj, dict):
      for inner_key, inner_val in condition_obj.items():
        condition_obj[inner_key] = cls.replace_symbols(inner_val, symbols)
    elif isinstance(condition_obj, list):
      for i in range(len(condition_obj)):
        condition_obj[i] = cls.replace_symbols(condition_obj[i], symbols)
    elif isinstance(condition_obj, str):
      condition_obj = convert_string(condition_obj)
    return condition_obj

  @property
  def admin_token(self):
    admin_token = self.config.get('admin_token', "")
    admin_token_map = self.config.get('admin_token_map', "")

    if admin_token:
      plain_token = admin_token
    else:
      aws_account_alias = get_account_alias(self.context.env)
      plain_token = admin_token_map.get(aws_account_alias)

    if plain_token is None:
      raise KeyError("NewRelic Admin Token not defined for {}".format(aws_account_alias))

    if self.config['token_kms_encrypted']:
      return kms_decrypt(self.clients['kms'], plain_token).plaintext

    return plain_token

  def create_alert_policy(self, policy):
    if not self.newrelic.alert_policy_exists(policy.name):
      self.newrelic.create_alert_policy(policy.name)
      logger.info("create alert policy {}".format(policy.name))
    return policy

  def populate_alert_policy_values(self, policy, service_type):
    policy.id = next(alert['id'] for alert in self.newrelic.all_alert_policies if alert['name'] == policy.name)
    policy.notification_channels = self.all_notification_channels[self.context.env]
    policy.remote_conditions = self.newrelic.get_policy_alert_conditions(policy.id)
    if service_type in ['aws_ec2', 'http_service']:
      policy.config_conditions = deepcopy(self.ec2_conditions)
    elif service_type in ['aws_ecs', 'aws_ecs_http']:
      policy.config_conditions = deepcopy(self.ecs_conditions)
    elif service_type in ['aws_lambda']:
      policy.config_conditions = deepcopy(self.lambda_alert_conditions)
    policy.remote_alert_nrql_conditions = self.newrelic.get_policy_alert_nrql_conditions(policy.id)
    policy.local_alert_nrql_conditions = deepcopy(self.local_alert_nrql_conditions)
    policy.remote_alert_apm_conditions = self.newrelic.get_policy_alert_apm_conditions(policy.id)
    policy.local_alert_apm_conditions = deepcopy(self.local_alert_apm_conditions)

  def delete_conditions_not_matching_config_values(self, policy):
    # Remove conditions with values that differ from config
    for condition in policy.remote_conditions:
      if condition['name'] in policy.config_conditions:
        config_condition = policy.config_conditions[condition['name']]
        for k, v in config_condition.items():
          if k in condition and condition[k] != v:
            self.newrelic.delete_policy_alert_condition(condition['id'])
            policy.remote_conditions = self.newrelic.get_policy_alert_conditions(policy.id)
            logger.info("delete condition {} with value {} from policy {}. ".format(condition['name'], condition[k], policy.name) +
                        "due to different current local config value {}".format(v))
            break

    return policy

  def create_infra_alert_conditions(self, policy):
    # Create alert conditions for policies
    remote_conditions = set([condition['name'] for condition in policy.remote_conditions])
    conditions_to_create = set(policy.config_conditions.keys()).difference(remote_conditions)

    for key in conditions_to_create:
      logger.info("create condition {} for policy {}".format(key, policy.name))
      self.newrelic.create_alert_condition(policy.config_conditions[key])

  def update_cloudfront_policy(self):
    # Update Cloudfront alert policies
    logger.info("update cloudfront alert policy")
    cloudfront = self.clients['cloudfront']
    pages = cloudfront.get_paginator('list_distributions').paginate()
    queue = []
    map_function = lambda x: (x['Id'], ', '.join(x['Aliases']['Items']))
    filtered_4xx_distributions = []
    for page in pages:
      for distribution in page['DistributionList']['Items']:
        tag_response = cloudfront.list_tags_for_resource(Resource=distribution['ARN'])
        # Remove from distribution list those that do not have tag nr_monitoring set to enabled
        for tag in tag_response['Tags']['Items']:
          if tag['Key'].lower() == "newrelic_4xx_monitoring" and tag['Value'].lower() == "enabled":
            filtered_4xx_distributions.append(distribution['Id'])
            break
      queue.extend(map(map_function, page['DistributionList']['Items']))

    # Create policy conditions
    meta = lambda error_rate, value, distribution_id, name, policy_id: {
      'select_value': 'provider.{}.Average'.format(error_rate),
      'comparison': 'above',
      'critical_threshold': {
        'duration_minutes': 5,
        'time_function': 'all',
        'value': value
      },
      'enabled': True,
      'event_type': 'LoadBalancerSample',
      'filter': {
        'and': [{
          'is': {
            'provider.distributionId': distribution_id
          }
        }]
      },
      'name': name,
      'integration_provider': 'CloudFrontDistribution',
      'policy_id': policy_id,
      'type': 'infra_metric',
    }

    policy = AlertPolicy(env=self.context.env, service='cloudfront')

    # Create cloudfront alert policy if it doesn't already exist
    if not self.newrelic.alert_policy_exists(policy.name):
      self.newrelic.create_alert_policy(policy.name)
      logger.info("create alert policy {}".format(policy.name))

    self.populate_alert_policy_values(policy, 'aws_fixture')
    self.add_alert_policy_to_notification_channels(policy)

    conditions = {}
    for id, alias in queue:
      if id in filtered_4xx_distributions:
        conditions['4xx Average {}'.format(alias)] = meta(
          'error4xxErrorRate', 10, id, '4xx Average {}'.format(alias), policy.id)
      conditions['5xx Average {}'.format(alias)] = meta(
        'error5xxErrorRate', 5, id, '5xx Average {}'.format(alias), policy.id)

    policy.config_conditions = deepcopy(conditions)
    # Infra alert conditions
    policy = self.delete_conditions_not_matching_config_values(policy)
    self.create_infra_alert_conditions(policy)

  def add_alert_policy_to_notification_channels(self, policy):
    # Add alert policy to notification channels if missing
    for channel in self.newrelic.all_notification_channels:
      if channel['name'] in policy.notification_channels and policy.id not in channel['links']['policy_ids']:
        self.newrelic.add_policy_channels(policy.id, [channel['id']])
        logger.info("add channel_ids {} to policy {}".format(policy.name, channel['id']))

  def add_policy_to_opsgenie_channel(self, policy, team_name):
    team_channel = self.newrelic.get_notification_channel_by_name(team_name)
    if not team_channel or team_channel['type'] != 'opsgenie':
      team_channel = self.newrelic.create_opsgenie_alert_channel(
        name=team_name,
        api_key=self.opsgenie_api_key,
        teams=[team_name]
      )

    if policy.id in team_channel['links']['policy_ids']:
      return

    chan_id = team_channel['id']

    self.newrelic.add_policy_channels(policy.id, [chan_id])
    logger.info("add OpsGenie channel id:%s for team %s to policy %s", chan_id, team_name, policy.name)

  def replace_symbols_in_condition(self, policy):
    # Replace symbols in config alert conditions
    for key, value in policy.config_conditions.items():
      policy.config_conditions[key] = self.replace_symbols(value, policy.symbols)

    # Replace symbols in config alert conditions
    for key, value in policy.local_alert_nrql_conditions.items():
      policy.local_alert_nrql_conditions[key] = self.replace_symbols(value, policy.symbols)

  def override_infra_alert_condition_values(self, policy, service_alert_overrides):
    # Update policy.config_conditions with overrides from service_registry
    for condition_name, override_obj in service_alert_overrides.items():
      if condition_name in policy.config_conditions.keys():
        for override_key, override_value in override_obj.items():
          if isinstance(override_value, dict):
            for inner_key, inner_val in override_value.items():
              policy.config_conditions[condition_name][override_key][inner_key] = inner_val
          else:
            policy.config_conditions[condition_name][override_key] = override_value
    logger.debug("Policy {} alert condition values:\n{}".format(policy.name, policy.config_conditions))

    return policy

  def update_alert_nrql_condition_if_different(self, local_alert_nrql_condition, policy):
    for remote_alert_nrql_condition in policy.remote_alert_nrql_conditions:
      if remote_alert_nrql_condition["name"] == local_alert_nrql_condition["name"]:
        relevant_fields = ["nrql", "terms", "enabled", "value_function", "violation_time_limit_seconds"]
        for key in relevant_fields:
          if local_alert_nrql_condition[key] != remote_alert_nrql_condition[key]:
            logger.info("Local alert nrql condition differs from remote alert nrql condition for {}-{}. Updating remote.".format(policy.env, policy.service))
            logger.info("Local: {}\nRemote: {}".format(local_alert_nrql_condition, remote_alert_nrql_condition))
            self.newrelic.put_policy_alert_nrql_condition(remote_alert_nrql_condition["id"], local_alert_nrql_condition)
            break

  def update_alert_apm_condition_if_different(self, local_alert_apm_condition, policy):
    for remote_alert_apm_condition in policy.remote_alert_apm_conditions:
      if remote_alert_apm_condition["name"] == local_alert_apm_condition["name"]:
        # Add fields that exist in the remote alert condition object but not in the local alert condition object.
        # This is done so that we can test equality.
        local_alert_apm_condition['id'] = remote_alert_apm_condition['id']
        local_alert_apm_condition['type'] = remote_alert_apm_condition['type']
        local_alert_apm_condition['entities'] = remote_alert_apm_condition['entities']

        local_alert_apm_condition['terms'].sort(key=lambda x: x['priority'])
        remote_alert_apm_condition['terms'].sort(key=lambda x: x['priority'])

        if local_alert_apm_condition != remote_alert_apm_condition:
          logger.info("Local alert apm condition differs from remote alert apm condition for {}-{}. Updating remote.".format(policy.env, policy.service))
          logger.debug("Local: {}\nRemote: {}".format(local_alert_apm_condition, remote_alert_apm_condition))
          self.newrelic.put_policy_alert_apm_condition(remote_alert_apm_condition["id"], local_alert_apm_condition)

  def override_alert_apm_condition_values(self, policy, service_alert_overrides):
    # Update policy.config_conditions with overrides from service_registry
    for condition_name, override_obj in service_alert_overrides.items():
      if condition_name in policy.local_alert_apm_conditions.keys():
        for override_key, override_value in override_obj.items():
          if isinstance(override_value, dict):
            for inner_key, inner_val in override_value.items():
              policy.local_alert_apm_conditions[condition_name][override_key][inner_key] = inner_val
          else:
            policy.local_alert_apm_conditions[condition_name][override_key] = override_value
    logger.debug("Policy {} APM alert condition values:\n{}".format(policy.name, policy.local_alert_apm_conditions))

    return policy

  def update_application_services_policies(self):
    for service_name, service_config in self.context.service_registry.iter_services(service_group="application_services"):
      service_environments = service_config['environments']
      service_alert_overrides = service_config.get('alerts', {})
      opsgenie_enabled = service_alert_overrides.get('opsgenie_enabled', True)
      opsgenie_team = service_config.get("team_opsgenie", "")
      service_type = service_config['type']

      if service_type not in ['aws_ec2', 'aws_ecs', 'aws_ecs_http', 'http_service']:
        continue

      logger.info("Service: {}".format(service_name))

      if self.context.env in service_environments:
        policy = AlertPolicy(env=self.context.env, service=service_name)

        logger.debug("Policy ID is {}".format(policy.id))

        # Create service alert policy if it doesn't already exist
        if not self.newrelic.alert_policy_exists(policy.name):
          self.newrelic.create_alert_policy(policy.name)
          logger.info("create alert policy {}".format(policy.name))

        # Update AlertPolicy object
        self.populate_alert_policy_values(policy, service_type)
        self.add_alert_policy_to_notification_channels(policy)
        self.replace_symbols_in_condition(policy)

        # Configure Opsgenie notifications for services running in the production account
        try:
          prod_account = EFConfig.ENV_ACCOUNT_MAP['prod']
          if (self.context.env in ["prod", "global.{}".format(prod_account), "mgmt.{}".format(prod_account)]
              and opsgenie_enabled and opsgenie_team):
            self.add_policy_to_opsgenie_channel(policy, opsgenie_team)
          elif not opsgenie_enabled or not opsgenie_team:
            logger.warning("Not adding opsgenie_channel {} for service {} alert policy.".format(opsgenie_team, service_name))
        except KeyError:
          pass

        # Infra alert conditions
        policy = self.override_infra_alert_condition_values(policy, service_alert_overrides)
        policy = self.delete_conditions_not_matching_config_values(policy)
        self.create_infra_alert_conditions(policy)

        # NRQL alert conditions
        remote_alert_nrql_condition_names = [remote_alert_nrql_condition['name'] for remote_alert_nrql_condition in policy.remote_alert_nrql_conditions]
        for condition_name, condition_value in policy.local_alert_nrql_conditions.items():
          if unicode(condition_name, "utf-8") not in remote_alert_nrql_condition_names:
            logger.info("Creating alert nrql condition {} for service {}".format(condition_name, service_name))
            self.newrelic.create_alert_nrql_condition(policy.id, condition_value)
          else:
            self.update_alert_nrql_condition_if_different(condition_value, policy)

        # APM alert conditions
        policy = self.override_alert_apm_condition_values(policy, service_alert_overrides)
        remote_alert_apm_condition_names = [remote_alert_apm_condition['name'] for remote_alert_apm_condition in policy.remote_alert_apm_conditions]
        for condition_name, condition_value in policy.local_alert_apm_conditions.items():
          if unicode(condition_name, "utf-8") not in remote_alert_apm_condition_names:
            applications = self.newrelic.get_applications(application_name=policy.name)

            if not len(applications):
              logger.info('No applications hosted for this policy: {}. Skip creating any APM alert'.format(policy.name))
              continue

            condition_value['entities'] = [applications[0]['id']]
            logger.info("Creating alert apm condition {} for service {}".format(condition_name, service_name))
            self.newrelic.create_alert_apm_condition(policy.id, condition_value)
          else:
            self.update_alert_apm_condition_if_different(condition_value, policy)

  def update_lambda_policies(self):
    platform_services = self.context.service_registry.iter_services(service_group="platform_services")
    application_services = self.context.service_registry.iter_services(service_group="application_services")
    for service_name, service_config in chain(platform_services, application_services):
      service_environments = service_config['environments']
      service_alert_overrides = service_config.get('alerts', {})
      opsgenie_enabled = service_alert_overrides.get('opsgenie_enabled', True)
      opsgenie_team = service_config.get("team_opsgenie", "")
      service_type = service_config['type']

      if service_type != 'aws_lambda':
        continue

      logger.info("Service: {}".format(service_name))

      if self.context.env in service_environments:
        policy = AlertPolicy(env=self.context.env, service=service_name)

        logger.debug("Policy ID is {}".format(policy.id))

        # Create service alert policy if it doesn't already exist
        if not self.newrelic.alert_policy_exists(policy.name):
          self.newrelic.create_alert_policy(policy.name)
          logger.info("create alert policy {}".format(policy.name))

        # Update AlertPolicy object
        self.populate_alert_policy_values(policy, service_type)
        self.add_alert_policy_to_notification_channels(policy)
        self.replace_symbols_in_condition(policy)

        # Configure Opsgenie notifications for services running in the production account
        try:
          prod_account = EFConfig.ENV_ACCOUNT_MAP['prod']
          if (self.context.env in ["prod", "global.{}".format(prod_account), "mgmt.{}".format(prod_account)]
              and opsgenie_enabled and opsgenie_team):
            self.add_policy_to_opsgenie_channel(policy, opsgenie_team)
          elif not opsgenie_enabled or not opsgenie_team:
            logger.warning("Not adding opsgenie_channel {} for service {} alert policy.".format(opsgenie_team, service_name))
        except KeyError:
          pass

        policy = self.override_infra_alert_condition_values(policy, service_alert_overrides)
        policy = self.delete_conditions_not_matching_config_values(policy)
        self.create_infra_alert_conditions(policy)

  def run(self):
    if self.context.env in self.all_notification_channels.keys():
      self.newrelic = NewRelic(self.admin_token)
      self.update_application_services_policies()
      self.update_lambda_policies()

      if self.context.env in ["prod"]:
        self.update_cloudfront_policy()
