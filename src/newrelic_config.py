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


