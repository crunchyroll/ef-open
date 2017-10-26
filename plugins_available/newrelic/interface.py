import json
import logging

import requests

logger = logging.getLogger(__name__)


class AlertPolicy:

  def __init__(self, env, service):
    self._env = env
    self._service = service
    self._id = None
    self.name = None
    self.notification_channels = None
    self.config_conditions = None
    self.conditions = None
    self.symbols = None
    self.set_name()
    self.set_symbols()

  @property
  def id(self):
    return self._id

  @id.setter
  def id(self, value):
    try:
      value = int(value)
    except ValueError:
      logger.error("Invalid value '{}' for policy id.".format(value))

    self._id = value
    self.set_symbols()

  @property
  def env(self):
    return self._env

  @env.setter
  def env(self, value):
    if isinstance(value, str):
      self._env = value
      self.set_name()
      self.set_symbols()
    else:
      logger.error("Invalid value '{}' for env.".format(value))

  @property
  def service(self):
    return self._service

  @service.setter
  def service(self, value):
    if isinstance(value, str):
      self._env = value
      self.set_name()
      self.set_symbols()
    else:
      logger.error("Invalid value '{}' for service.".format(value))

  def set_name(self):
    self.name = "{}-{}".format(self.env, self.service)

  def set_symbols(self):
    self.symbols = {
      "ENV": self.env,
      "POLICY_ID": self.id,
      "SERVICE": self.service
    }


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

  def create_alert_cond(self, condition):
    print(json.dumps({ "data": condition }))
    add_condition = requests.post(
      url='https://infra-api.newrelic.com/v2/alerts/conditions',
      headers=self.auth_header,
      data=json.dumps({ "data": condition })
    )
    add_condition.raise_for_status()
    return add_condition.json()['data']['id']

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

  def delete_policy(self, policy_id):
    delete_policy = requests.delete(
      url='https://api.newrelic.com/v2/alerts_policies/{}.json'.format(policy_id),
      headers=self.auth_header
    )
    delete_policy.raise_for_status()
