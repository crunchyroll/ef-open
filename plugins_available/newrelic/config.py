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

encrypted_token = ("AQICAHgnK9qmyWCnKC++2JqZC4P/zUXLQ2qPfIfa7a2gf7JRfgG8SMLWBlNuxHkQeku62gNkAAAAfjB8BgkqhkiG9w0BBwagb"
  "zBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMfxQ3LF3UcfhBxY6QAgEQgDt0Oil5pNQtcixGWz4QA9ZBPi/XmEjKkjf8XzGnXDtXnS+vV"
  "4xk6Ffew6qGUQcE+e0Hx/ctx996b4eJPQ==")

warning_channels = ['slack-warn']
critical_channels = ['slack-critical']
alert_environments = ["staging", "prod"]
