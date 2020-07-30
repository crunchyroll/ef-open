import json
import logging

import requests

logger = logging.getLogger(__name__)


class AlertPolicy(object):

  def __init__(self, env, service):
    self._env = env
    self._service = service
    self._id = None
    self.name = None
    self.notification_channels = None
    self.config_conditions = None
    self.remote_conditions = None
    self.local_alert_nrql_conditions = None
    self.remote_alert_nrql_conditions = None
    self.local_alert_apm_conditions = None
    self.remote_alert_apm_conditions = None
    self.symbols = None
    self.set_name()
    self.set_symbols()

  @property
  def id(self):
    return self._id

  @id.setter
  def id(self, value):
    try:
      self._id = int(value)
      self.set_symbols()
    except ValueError:
      logger.error("Invalid value '{}' for policy id.".format(value))

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


class NewRelic(object):

  def __init__(self, admin_token):
    self.admin_token = admin_token
    self.auth_header = {'X-Api-Key': self.admin_token, 'Content-Type': 'application/json'}
    self.all_alert_policies = None
    self.all_notification_channels = None
    self.refresh_alert_policies()
    self.refresh_notification_channels()

  def iterative_get(self, endpoint_url, response_key, params=None):
    params = params if params else {}
    response = []
    while True:
      r = requests.get(
        url=endpoint_url,
        headers=self.auth_header,
        params=params
      )
      r.raise_for_status()
      response.extend(r.json()[response_key])
      try:
        endpoint_url = r.links['next']['url']
      except KeyError:
        # This parameter comes only on GET https://infra-api.newrelic.com/v2/alerts/conditions
        if 'meta' not in r.json():
          break

        meta = r.json()['meta']

        new_offset = meta['offset'] + meta['limit']
        if new_offset < meta['total']:
          params['offset'] = new_offset
        else:
          break
    return response

  def refresh_alert_policies(self):
    self.all_alert_policies = self.iterative_get(
      endpoint_url='https://api.newrelic.com/v2/alerts_policies.json',
      response_key='policies'
    )

  def refresh_notification_channels(self):
    self.all_notification_channels = self.iterative_get(
      endpoint_url='https://api.newrelic.com/v2/alerts_channels.json',
      response_key='channels'
    )

  def alert_policy_exists(self, policy_name):
    """Check to see if an alert policy exists in NewRelic. Return True if so, False if not"""
    if next((policy for policy in self.all_alert_policies if policy['name'] == policy_name), False):
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
    self.refresh_alert_policies()
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

  def create_alert_condition(self, condition):
    add_condition = requests.post(
      url='https://infra-api.newrelic.com/v2/alerts/conditions',
      headers=self.auth_header,
      data=json.dumps({"data": condition})
    )
    add_condition.raise_for_status()
    return

  def get_policy_alert_conditions(self, policy_id):
    return self.iterative_get(
      endpoint_url='https://infra-api.newrelic.com/v2/alerts/conditions',
      response_key='data',
      params={'policy_id': policy_id}
    )

  def delete_policy_alert_condition(self, condition_id):
    delete_condition = requests.delete(
      url='https://infra-api.newrelic.com/v2/alerts/conditions/{}'.format(condition_id),
      headers=self.auth_header
    )
    delete_condition.raise_for_status()
    return

  def create_alert_nrql_condition(self, policy_id, condition):
    add_condition = requests.post(
      url='https://api.newrelic.com/v2/alerts_nrql_conditions/policies/{}.json'.format(policy_id),
      headers=self.auth_header,
      data=json.dumps({"nrql_condition": condition})
    )
    add_condition.raise_for_status()
    return

  def get_policy_alert_nrql_conditions(self, policy_id):
    return self.iterative_get(
      endpoint_url='https://api.newrelic.com/v2/alerts_nrql_conditions.json',
      response_key='nrql_conditions',
      params={'policy_id': policy_id}
    )

  def put_policy_alert_nrql_condition(self, condition_id, condition):
    put_condition = requests.put(
      url='https://api.newrelic.com/v2/alerts_nrql_conditions/{}.json'.format(condition_id),
      headers=self.auth_header,
      data=json.dumps({"nrql_condition": condition})
    )
    put_condition.raise_for_status()
    return


  def create_alert_apm_condition(self, policy_id, condition):
    add_condition = requests.post(
      url='https://api.newrelic.com/v2/alerts_conditions/policies/{}.json'.format(policy_id),
      headers=self.auth_header,
      data=json.dumps({"condition": condition})
    )
    add_condition.raise_for_status()
    return

  def get_policy_alert_apm_conditions(self, policy_id):
    return self.iterative_get(
      endpoint_url='https://api.newrelic.com/v2/alerts_conditions.json',
      response_key='conditions',
      params={'policy_id': policy_id}
    )

  def put_policy_alert_apm_condition(self, condition_id, condition):
    put_condition = requests.put(
      url='https://api.newrelic.com/v2/alerts_conditions/{}.json'.format(condition_id),
      headers=self.auth_header,
      data=json.dumps({"condition": condition})
    )
    put_condition.raise_for_status()
    return

  def get_applications(self, application_name=''):
    return self.iterative_get(
      endpoint_url='https://api.newrelic.com/v2/applications.json',
      response_key='applications',
      params={'filter[name]': application_name}
    )

  def create_alert_channel(self, name, channel_type, configuration):
    create_channel = requests.post(
      url='https://api.newrelic.com/v2/alerts_channels.json',
      headers=self.auth_header,
      json={
        'channel': {
          'name': name,
          'type': channel_type,
          'configuration': configuration
        }
      })
    create_channel.raise_for_status()
    return create_channel.json()['channels'][0]

  def create_opsgenie_alert_channel(self, name, api_key, teams=(), tags=(), recipients=()):
    if any([isinstance(arg, basestring) for arg in [teams, tags, recipients]]):
      raise ValueError("teams:{}, tags:{} and recipients:{} should not be of type string:".format(*map(type, [teams, tags, recipients])))

    og_channel_configuration = {
      'api_key': api_key,
      'teams': ','.join(teams),
      'tags': ','.join(tags),
      'recipients': ','.join(recipients)
    }
    return self.create_alert_channel(name, 'opsgenie', og_channel_configuration)

  def get_notification_channel_by_name(self, name):
    alert_channels = self.get_all_notification_channels()
    for channel in alert_channels:
      if channel['name'] == name:
        return channel
    return None

  def get_all_notification_channels(self, refresh=False):
    if self.all_notification_channels and not refresh:
      return self.all_notification_channels

    self.all_notification_channels = self.iterative_get(
      endpoint_url='https://api.newrelic.com/v2/alerts_channels.json',
      response_key='channels'
    )
    return self.all_notification_channels
