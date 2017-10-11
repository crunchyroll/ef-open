import boto3
from copy import deepcopy
import requests
import json
import logging
import itertools
from ef_service_registry import EFServiceRegistry
from ef_utils import kms_decrypt
import newrelic_config

class NewRelic:

  def __init__(self, admin_token):
    self.admin_token = admin_token
    self.auth_header =  {'X-Api-Key': self.admin_token, 'Content-Type': 'application/json'}
    self.all_alerts = None
    self.all_channels = None
    self.refresh_all_alerts()
    self.refresh_all_channels()

  def refresh_all_alerts(self):
    get_alerts = requests.get(
      url='https://api.newrelic.com/v2/alerts_policies.json',
      headers=self.auth_header
    )
    get_alerts.raise_for_status()
    self.all_alerts = get_alerts.json()['policies']

  def refresh_all_channels(self):
    get_channels = requests.get(
      url='https://api.newrelic.com/v2/alerts_channels.json',
      headers=self.auth_header
    )
    get_channels.raise_for_status()
    self.all_channels = get_channels.json()['channels']

  def alert_policy_exists(self, policy_name):
    """Check to see if an alert policy exists in NewRelic. Return True if so, False if not"""
    if next((policy for policy in self.all_alerts if policy['name'] == policy_name), False):
      return True

  def create_alert_policy(self, policy_name):
    """Creates an alert policy in NewRelic"""
    policy_data = { 'policy': { 'incident_preference': 'PER_POLICY', 'name': policy_name } }
    create_policy = requests.post(
      'https://api.newrelic.com/v2/alerts_policies.json',
      headers=self.auth_header,
      data=json.dumps(policy_data))
    create_policy.raise_for_status()
    policy_id = create_policy.json()['policy']['id']
    self.refresh_all_alerts()
    return policy_id

  def add_policy_channels(self, policy_id, channel_ids):
    payload = { 'policy_id': policy_id, 'channel_ids': channel_ids}
    put_channels = requests.put(
      url='https://api.newrelic.com/v2/alerts_policy_channels.json',
      headers=self.auth_header,
      params=payload
    )
    put_channels.raise_for_status()
    return

  def delete_policy_channel(self, policy_id, channel_id):
    payload = {'policy_id': policy_id, 'channel_id': channel_id}
    delete_channel = requests.delete(
      url='https://api.newrelic.com/v2/alerts_policy_channels.json',
      headers=self.auth_header,
      params=payload
    )
    delete_channel.raise_for_status()
    return

  def create_alert_cond(self, policy_id, condition_name, alert_condition, threshold, ec2_tag, event_type):
    payload = {
       "data":{
          "type":"infra_metric",
          "name":condition_name,
          "enabled":True,
          "filter": {"and":[{"is":{"ec2Tag_Name":ec2_tag}}]},
          "policy_id":policy_id,
          "event_type":event_type,
          "select_value":alert_condition,
          "comparison":"above",
          "critical_threshold":{
             "value":threshold,
             "duration_minutes":5,
             "time_function":"all"
          }
       }
    }
    add_policy = requests.post(
      url='https://infra-api.newrelic.com/v2/alerts/conditions',
      headers=self.auth_header,
      data=json.dumps(payload)
    )
    add_policy.raise_for_status()
    return add_policy.json()['data']['id']

  def get_policy_alert_conditions(self, policy_id):
    get_conditions = requests.get(
      url="https://infra-api.newrelic.com/v2/alerts/conditions",
      headers=self.auth_header,
      params={ 'policy_id': policy_id }
    )
    get_conditions.raise_for_status()
    return get_conditions.json()['data']

  def delete_policy_alert_condition(self, condition_id):
    delete_condition = requests.delete(
      url='https://infra-api.newrelic.com/v2/alerts/conditions/{}'.format(condition_id),
      headers=self.auth_header
    )
    delete_condition.raise_for_status()
    return

def main():
  kms = boto3.client('kms')
  api_token = kms_decrypt(kms, newrelic_config.encrypted_token)
  registry = EFServiceRegistry()
  alert_environments = ["staging", "prod"]
  newrelic = NewRelic(admin_token=api_token)
  logging.basicConfig(level=logging.INFO)
  logger = logging.getLogger(__name__)

  for service in registry.iter_services(service_group="application_services"):
    service_name = service[0]
    service_environments = service[1]['environments']
    service_alerts = service[1]['alerts'] if "alerts" in service[1] else {}

    # Set service alert values
    alert_conditions = deepcopy(newrelic_config.conditions)
    for key, value in alert_conditions.items():
      for level in ["critical", "warning"]:
        if "{}_{}".format(value['sr_name'], level) in service_alerts:
          value["{}_threshold".format(level)] = service_alerts["{}_{}".format(value['sr_name'], level)]

    # Iterate through all permutations of environment/service
    policy_names = [service_name, "{}-warn".format(service_name)]
    environments = [env for env in alert_environments if env in service_environments]
    for env, policy in itertools.product(environments, policy_names):

      policy_name = "-".join((env, policy))
      alert_level = "warning" if "-warn" in policy_name else "critical"
      alert_channels = newrelic_config.critical_channels if alert_level == "critical" and env == "prod" \
                        else newrelic_config.warning_channels

      # Create service alert policy if it doesn't already exist
      if not newrelic.alert_policy_exists(policy_name):
        newrelic.create_alert_policy(policy_name)
        logger.info("Create alert policy {}".format(policy_name))

      policy_id = next(policy['id'] for policy in newrelic.all_alerts if policy['name'] == policy_name)

      # Add notification channels to alert policy
      for channel in newrelic.all_channels:
        if channel['name'] in alert_channels and policy_id not in channel['links']['policy_ids']:
          newrelic.add_policy_channels(policy_id, [channel['id']])
          logger.info("Added channel_ids {} to policy {}".format(policy_name, channel['id']))

      # Remove conditions with values that differ from what's in the service_registry/default
      current_conditions = newrelic.get_policy_alert_conditions(policy_id)
      for condition in current_conditions:
        if condition['name'] in alert_conditions:
            current_threshold = condition['critical_threshold']['value']
            config_threshold = alert_conditions[condition['name']]['{}_threshold'.format(alert_level)]
            if current_threshold != config_threshold:
              newrelic.delete_policy_alert_condition(condition['id'])
              logger.info("deleted condition {} from policy {}.".format(condition['name'], policy_name) + \
                          "current value differs from config")

      # Create alert conditions for policies
      current_conditions = newrelic.get_policy_alert_conditions(policy_id)
      for key, value in alert_conditions.items():
        if not any(d['name'] == key for d in current_conditions):
          newrelic.create_alert_cond(
            policy_id=policy_id,
            condition_name=key,
            alert_condition=value['alert_condition'],
            threshold=value['{}_threshold'.format(alert_level)],
            ec2_tag=policy_name.replace("-warn", ""),
            event_type=value['event_type']
          )
          logger.info("created alert condition {} for policy {}".format(key, policy_name))

if __name__ == "__main__":
  main()
