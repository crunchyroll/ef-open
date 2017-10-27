# NewRelic admin api token
admin_token = ""

# Indicates whether the admin_token has been encrypted by KMS.
# If True, any accounts tied to environments in alert_environments will need decrypt privileges to this key.
token_kms_encrypted = True

# Map of environments that alert policies will be created for along with the notification channels that they will alert on.
env_notification_map = {
  "staging": [],
  "prod": []
}

# Alert conditions to be used for each service along with default thresholds. The key is the condition name
# that will appear in NewRelic and must match the "name" value in the condition object.
# Default values can be overridden on a per-service basis. See the readme for examples.
# Variables available are: ENV, SERVICE, and POLICY_ID
alert_conditions = {
  "cpu_percent": {
     "type":"infra_metric",
     "name":"cpu_percent",
     "enabled": True,
     "filter": {"and":[{"is": {"ec2Tag_Name":"{{ENV}}-{{SERVICE}}"}}]},
     "policy_id": "{{POLICY_ID}}",
     "event_type":"SystemSample",
     "select_value":"cpuPercent",
     "comparison":"above",
     "critical_threshold": {
        "value": 90,
        "duration_minutes": 5,
        "time_function":"all"
     }
  },
  "memory_used": {
    "type": "infra_metric",
    "name": "memory_used",
    "enabled": True,
    "filter": {"and":[{"is": {"ec2Tag_Name":"{{ENV}}-{{SERVICE}}"}}]},
    "policy_id": "{{POLICY_ID}}",
    "event_type": "SystemSample",
    "select_value": "memoryUsedBytes/memoryTotalBytes*100",
    "comparison": "above",
    "critical_threshold": {
      "value": 90,
      "duration_minutes": 5,
      "time_function":"all"
    }
  },
  "disk_used": {
    "type": "infra_metric",
    "name": "disk_used",
    "enabled": True,
    "filter": {"and": [{"is": {"ec2Tag_Name": "{{ENV}}-{{SERVICE}}"}}]},
    "policy_id": "{{POLICY_ID}}",
    "event_type": "StorageSample",
    "select_value": "diskUsedPercent",
    "comparison": "above",
    "critical_threshold": {
      "value": 90,
      "duration_minutes": 5,
      "time_function": "all"
    }
  }
}
