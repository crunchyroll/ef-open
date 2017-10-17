# NewRelic admin api token, encrypted by KMS. Any accounts tied to environments in alert_environments will need decrypt
#  privileges to this key.
encrypted_token = ""

# Notification channels in NewRelic to be used for warning and critical alert levels
# ex. warning_channels = ["slack-warn"]
warning_channels = []
critical_channels = []

# Environments for which alerts should be created. Should be in ef_site_config.ENV_ACCOUNT_MAP
# ex. alert_environments = ["staging", "prod"]
alert_environments = []

# Environments which will trigger critical alert channels when a critical condition threshold is passed. Otherwise,
# warning channels will be used.
# ex. critical_alert_environments = ["prod"]
critical_alert_environments = []

# Alert conditions to be used for each service along with default thresholds. This currently supports infrastructure
# alerts filtering based on the ec2 name tags created by ef-cf. The key in the conditions dict is the condition name
# that will appear in NewRelic. The sr_name value is what is used inside the service registry to set service-specific
# condition thresholds that differ from the defaults. See the readme for examples.
conditions = {
  'memoryUsed': {
    'event_type': 'SystemSample',
    'alert_condition': 'memoryUsedBytes/memoryTotalBytes*100',
    'sr_name': 'memory',
    'warning_threshold': 80,
    'critical_threshold': 90
  },
  'cpuPercent': {
    'event_type': 'SystemSample',
    'alert_condition': 'cpuPercent',
    'sr_name': 'cpu',
    'warning_threshold': 80,
    'critical_threshold': 90
  },
  'diskUsed': {
    'event_type': 'StorageSample',
    'alert_condition': 'diskUsedPercent',
    'sr_name': 'disk',
    'warning_threshold': 80,
    'critical_threshold': 90
  }
}
