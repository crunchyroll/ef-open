from copy import deepcopy
import logging

from ef_plugin import ef_plugin
from ef_utils import kms_decrypt

import config
from interface import NewRelic


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@ef_plugin('ef-generate')
class NewRelicAlerts(object):

  def __init__(self):
    # load config settings
    self.alert_environments = config.alert_environments
    self.critical_alert_environments = config.critical_alert_environments
    self.conditions = config.alert_conditions
    self.encrypted_token = config.encrypted_token
    self.critical_channels = config.critical_channels
    self.warning_channels = config.warning_channels

  def replace_symbols(self, condition_obj):
    def convert_string(string):
      for symbol in RESOLVED:
        if symbol in string:
          string = string.replace("{{" + symbol + "}}", str(RESOLVED[symbol]))
      return string

    if isinstance(condition_obj, dict):
      for inner_key, inner_val in condition_obj.items():
        condition_obj[inner_key] = self.replace_symbols(inner_val)
    elif isinstance(condition_obj, list):
      for i in range(len(condition_obj)):
        condition_obj[i] = self.replace_symbols(condition_obj[i])
    elif isinstance(condition_obj, str):
      condition_obj = convert_string(condition_obj)
    return condition_obj

  def set_symbol_values(self, policy_id, service):
    symbols = {
      "ENV": self.context.env,
      "POLICY_ID": policy_id,
      "SERVICE": service
    }
    return symbols

  def run(self):
    if self.context.env in self.alert_environments:
      admin_token = kms_decrypt(self.clients['kms'], self.encrypted_token)
      newrelic = NewRelic(admin_token)
      
      for service in self.context.service_registry.iter_services(service_group="application_services"):
        service_name = service[0]
        service_environments = service[1]['environments']
        service_alerts = service[1]['alerts'] if "alerts" in service[1] else {}

        if self.context.env in service_environments:
          # Set service-level alert condition values
          alert_conditions = deepcopy(self.conditions)
          for key, value in alert_conditions.items():
            for level in ["critical", "warning"]:
              if "{}_{}".format(value['name'], level) in service_alerts:
                value["{}_threshold".format(level)] = int(service_alerts["{}_{}".format(value['name'], level)])

          # Configure the env-service and env-service-warn policies
          base_policy_name = "{}-{}".format(self.context.env, service_name)
          for policy_name in [base_policy_name, "{}-warn".format(base_policy_name)]:
            alert_level = "warning" if "-warn" in policy_name else "critical"
            if alert_level == "critical" and self.context.env in self.critical_alert_environments:
              alert_channels = self.critical_channels
            else:
              alert_channels = self.warning_channels

            # Create service alert policy if it doesn't already exist
            if not newrelic.alert_policy_exists(policy_name):
              newrelic.create_alert_policy(policy_name)
              logger.info("create alert policy {}".format(policy_name))

            policy_id = next(policy['id'] for policy in newrelic.all_alerts if policy['name'] == policy_name)

            # Add notification channels to alert policy
            for channel in newrelic.all_channels:
              if channel['name'] in alert_channels and policy_id not in channel['links']['policy_ids']:
                newrelic.add_policy_channels(policy_id, [channel['id']])
                logger.info("add channel_ids {} to policy {}".format(policy_name, channel['id']))

            # Remove conditions with threshold values that differ from config
            current_conditions = newrelic.get_policy_alert_conditions(policy_id)
            for condition in current_conditions:
              if condition['name'] in alert_conditions:
                current_threshold = condition['critical_threshold']['value']
                config_threshold = alert_conditions[condition['name']]['{}_threshold'.format(alert_level)]
                if current_threshold != config_threshold:
                  newrelic.delete_policy_alert_condition(condition['id'])
                  logger.info("delete condition {} from policy {}. ".format(condition['name'], policy_name) + \
                              "current value differs from config")

            # Create alert conditions for policies
            symbols = self.set_symbol_values(policy_id=policy_id, service=service_name)
            current_conditions = newrelic.get_policy_alert_conditions(policy_id)
            for key, value in alert_conditions.items():
              value = self.replace_symbols(value, symbols)
              if not any(d['name'] == key for d in current_conditions):

                # newrelic.create_alert_cond(
                #   policy_id=policy_id,
                #   condition_name=key,
                #   select_value=value['select_value'],
                #   threshold=value['{}_threshold'.format(alert_level)],
                #   ec2_tag=policy_name.replace("-warn", ""),
                #   event_type=value['event_type']
                # )
                # logger.info("create alert condition {} for policy {}".format(key, policy_name))
# TODO: Update create alert condition
# TODO: Create alert policy class
# TODO: Replace any value in sr override
