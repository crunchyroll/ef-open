# NewRelic admin api token, encrypted by KMS
encrypted_token = ""

# Notification channels to be used for warning and critical alert levels
# ex. warning_channels = ["slack-warn"]
warning_channels = []
critical_channels = []

# Environments for which alerts should be created. Should be in ef_site_config.ENV_ACCOUNT_MAP
# ex. alert_environments = ["staging", "prod"]
alert_environments = []

# Alert conditions to be used for each service along with default thresholds
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
