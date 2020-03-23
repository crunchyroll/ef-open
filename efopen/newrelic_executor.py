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
    self.conditions = self.config['alert_conditions']
    self.admin_token = self.config['admin_token']
    self.all_notification_channels = self.config['env_notification_map']
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

  def create_policy(self, service_name):
    policy = AlertPolicy(env=self.context.env, service=service_name)

    # Create service alert policy if it doesn't already exist
    if not self.newrelic.alert_policy_exists(policy.name):
      self.newrelic.create_alert_policy(policy.name)
      logger.info("create alert policy {}".format(policy.name))
    policy.id = next(alert['id'] for alert in self.newrelic.all_alerts if alert['name'] == policy.name)
    policy.notification_channels = self.all_notification_channels[self.context.env]
    policy.conditions = self.newrelic.get_policy_alert_conditions(policy.id)
    policy.config_conditions = deepcopy(self.conditions)
    return policy

  def remove_redundant_policy_conditions(self, policy):
    # Remove conditions with values that differ from config
    for condition in policy.conditions:
      if condition['name'] in policy.config_conditions:
        config_condition = policy.config_conditions[condition['name']]
        for k, v in config_condition.items():
          if condition[k] != v:
            self.newrelic.delete_policy_alert_condition(condition['id'])
            policy.conditions = self.newrelic.get_policy_alert_conditions(policy.id)
            logger.info("delete condition {} from policy {}. ".format(condition['name'], policy.name) + \
                        "current value differs from config")
            break

    return policy

  def create_policy_conditions(self, policy):
    # Create alert conditions for policies
    for key, value in policy.config_conditions.items():
      if not any(d['name'] == key for d in policy.conditions):
        self.newrelic.create_alert_cond(policy.config_conditions[key])
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

    policy = self.create_policy('cloudfront')
    conditions = {}
    for id, alias in queue:
      conditions['cloudfront-{}-{}'.format(id, '4xxErrorRate')] = meta(
        '4xxErrorRate', 10, id, '4xx Average {}'.format(alias), policy.id)
      conditions['cloudfront-{}-{}'.format(id, '5xxErrorRate')] = meta(
        '5xxErrorRate', 5, id, '5xx Average {}'.format(alias), policy.id)

    policy.config_conditions = deepcopy(conditions)

    policy = self.remove_redundant_policy_conditions(policy)
    self.create_policy_conditions(policy)

  def update_application_services_policies(self):
    for service in self.context.service_registry.iter_services(service_group="application_services"):
      service_name = service[0]
      service_environments = service[1]['environments']
      service_alert_overrides = service[1]['alerts'] if "alerts" in service[1] else {}
      if self.context.env in service_environments:

        policy = self.create_policy(service_name)

        # Add alert policy to notification channels if missing
        for channel in self.newrelic.all_channels:
          if channel['name'] in policy.notification_channels and policy.id not in channel['links']['policy_ids']:
            self.newrelic.add_policy_channels(policy.id, [channel['id']])
            logger.info("add channel_ids {} to policy {}".format(policy.name, channel['id']))

        # Replace symbols in config alert conditions
        for key, value in policy.config_conditions.items():
          policy.config_conditions[key] = self.replace_symbols(value, policy.symbols)

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

        policy = self.remove_redundant_policy_conditions(policy)
        self.create_policy_conditions(policy)

  def run(self):
    if self.context.env in self.all_notification_channels.keys():
      if self.config['token_kms_encrypted']:
        self.admin_token = kms_decrypt(self.clients['kms'], self.admin_token).plaintext

      self.newrelic = NewRelic(self.admin_token)
      self.update_application_services_policies()

      if self.context.env in ["prod"]:
        self.update_cloudfront_policy()
