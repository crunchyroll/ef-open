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

  def run(self):
    if self.context.env in self.all_notification_channels.keys():
      if self.config['token_kms_encrypted']:
        self.admin_token = kms_decrypt(self.clients['kms'], self.admin_token).plaintext

      newrelic = NewRelic(self.admin_token)
      for service in self.context.service_registry.iter_services(service_group="application_services"):
        service_name = service[0]
        service_environments = service[1]['environments']
        service_alert_overrides = service[1]['alerts'] if "alerts" in service[1] else {}
        if self.context.env in service_environments:

          policy = AlertPolicy(env=self.context.env, service=service_name)
          # Create service alert policy if it doesn't already exist
          if not newrelic.alert_policy_exists(policy.name):
            newrelic.create_alert_policy(policy.name)
            logger.info("create alert policy {}".format(policy.name))
          policy.id = next(alert['id'] for alert in newrelic.all_alerts if alert['name'] == policy.name)
          policy.notification_channels = self.all_notification_channels[self.context.env]
          policy.conditions = newrelic.get_policy_alert_conditions(policy.id)
          policy.config_conditions = deepcopy(self.conditions)

          # Add alert policy to notification channels if missing
          for channel in newrelic.all_channels:
            if channel['name'] in policy.notification_channels and policy.id not in channel['links']['policy_ids']:
              newrelic.add_policy_channels(policy.id, [channel['id']])
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

          # Remove conditions with values that differ from config
          for condition in policy.conditions:
            if condition['name'] in policy.config_conditions:
              config_condition = policy.config_conditions[condition['name']]
              for k, v in config_condition.items():
                if condition[k] != v:
                  newrelic.delete_policy_alert_condition(condition['id'])
                  policy.conditions = newrelic.get_policy_alert_conditions(policy.id)
                  logger.info("delete condition {} from policy {}. ".format(condition['name'], policy.name) + \
                              "current value differs from config")
                  break

          # Create alert conditions for policies
          for key, value in policy.config_conditions.items():
            if not any(d['name'] == key for d in policy.conditions):
              newrelic.create_alert_cond(policy.config_conditions[key])
              logger.info("create condition {} for policy {}".format(key, policy.name))
