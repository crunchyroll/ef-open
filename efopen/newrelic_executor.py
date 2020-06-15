from copy import deepcopy
import logging

from ef_config import EFConfig
from ef_utils import kms_decrypt
from newrelic_interface import NewRelic, AlertPolicy


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NewRelicAlerts(object):

  def __init__(self, context, clients):
    self.config = EFConfig.PLUGINS['newrelic']
    self.conditions = self.config.get('alert_conditions', {})
    self.local_alert_nrql_conditions = self.config.get('alert_nrql_conditions', {})
    self.admin_token = self.config.get('admin_token', "")
    self.all_notification_channels = self.config.get('env_notification_map', {})
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

  def create_alert_policy(self, policy):
    if not self.newrelic.alert_policy_exists(policy.name):
      self.newrelic.create_alert_policy(policy.name)
      logger.info("create alert policy {}".format(policy.name))
    return policy

  def populate_alert_policy_values(self, policy):
    policy.id = next(alert['id'] for alert in self.newrelic.all_alert_policies if alert['name'] == policy.name)
    policy.notification_channels = self.all_notification_channels[self.context.env]
    policy.remote_conditions = self.newrelic.get_policy_alert_conditions(policy.id)
    policy.config_conditions = deepcopy(self.conditions)
    policy.remote_alert_nrql_conditions = self.newrelic.get_policy_alert_nrql_conditions(policy.id)
    policy.local_alert_nrql_conditions = deepcopy(self.local_alert_nrql_conditions)

  def delete_conditions_not_matching_config_values(self, policy):
    # Remove conditions with values that differ from config
    for condition in policy.remote_conditions:
      if condition['name'] in policy.config_conditions:
        config_condition = policy.config_conditions[condition['name']]
        for k, v in config_condition.items():
          if condition[k] != v:
            self.newrelic.delete_policy_alert_condition(condition['id'])
            policy.remote_conditions = self.newrelic.get_policy_alert_conditions(policy.id)
            logger.info("delete condition {} from policy {}. ".format(condition['name'], policy.name) +
                        "current value differs from config")
            break

    return policy

  def create_infra_alert_conditions(self, policy):
    # Create alert conditions for policies
    for key, value in policy.config_conditions.items():
      if not any(condition['name'] == key for condition in policy.remote_conditions):
        self.newrelic.create_alert_condition(policy.config_conditions[key])
        logger.info("create condition {} for policy {}".format(key, policy.name))

  def update_cloudfront_policy(self):
    # Update Cloudfront alert policies
    logger.info("update cloudfront alert policy")
    cloudfront = self.clients['cloudfront']
    distribution_list = cloudfront.list_distributions()['DistributionList']
    map_function = lambda x: (x['Id'], ', '.join(x['Aliases']['Items']))
    queue = map(map_function, distribution_list['Items'])

    while distribution_list['IsTruncated']:
      distribution_list = cloudfront.list_distributions(Marker=distribution_list['NextMarker'])['DistributionList']
      queue.extend(map(map_function, distribution_list['Items']))

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

    self.populate_alert_policy_values(policy)

    conditions = {}
    for id, alias in queue:
      conditions['4xx Average {}'.format(alias)] = meta(
        '4xxErrorRate', 10, id, '4xx Average {}'.format(alias), policy.id)
      conditions['5xx Average {}'.format(alias)] = meta(
        '5xxErrorRate', 5, id, '5xx Average {}'.format(alias), policy.id)

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
        # Add fields that exist in the remote alert condition object but not in the local alert condition object.
        # This is done so that we can test equality.
        local_alert_nrql_condition['id'] = remote_alert_nrql_condition['id']
        local_alert_nrql_condition['type'] = remote_alert_nrql_condition['type']

        if local_alert_nrql_condition != remote_alert_nrql_condition:
          logger.info("Local alert nrql condition differs from remote alert nrql condition for {}-{}. Updating remote.".format(policy.env,policy.service))
          logger.debug("Local: {}\nRemote: {}".format(local_alert_nrql_condition, remote_alert_nrql_condition))
          self.newrelic.put_policy_alert_nrql_condition(remote_alert_nrql_condition["id"], local_alert_nrql_condition)

  def update_application_services_policies(self):
    for service in self.context.service_registry.iter_services(service_group="application_services"):
      service_name = service[0]
      service_environments = service[1]['environments']
      service_alert_overrides = service[1]['alerts'] if "alerts" in service[1] else {}

      if self.context.env in service_environments:
        policy = AlertPolicy(env=self.context.env, service=service_name)

        # Create service alert policy if it doesn't already exist
        if not self.newrelic.alert_policy_exists(policy.name):
          self.newrelic.create_alert_policy(policy.name)
          logger.info("create alert policy {}".format(policy.name))

        # Update AlertPolicy object
        self.populate_alert_policy_values(policy)
        self.add_alert_policy_to_notification_channels(policy)
        self.replace_symbols_in_condition(policy)

        # Infra alert conditions
        policy = self.override_infra_alert_condition_values(policy, service_alert_overrides)
        policy = self.delete_conditions_not_matching_config_values(policy)
        self.create_infra_alert_conditions(policy)

        # NRQL alert conditions
        remote_alert_nrql_condition_names = [remote_alert_nrql_condition['name'] for remote_alert_nrql_condition in policy.remote_alert_nrql_conditions]
        for condition_name, condition_value in policy.local_alert_nrql_conditions.items():
          if condition_name not in remote_alert_nrql_condition_names:
            self.newrelic.create_alert_nrql_condition(policy.id, condition_value)
          else:
            self.update_alert_nrql_condition_if_different(condition_value, policy)

  def run(self):
    if self.context.env in self.all_notification_channels.keys():
      if self.config['token_kms_encrypted']:
        self.admin_token = kms_decrypt(self.clients['kms'], self.admin_token).plaintext

      self.newrelic = NewRelic(self.admin_token)
      self.update_application_services_policies()

      # TODO: Fix the cloudfront code
      # if self.context.env in ["prod"]:
      #  self.update_cloudfront_policy()
