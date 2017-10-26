### Purpose 
Automate the creation of baseline NewRelic ec2 infrastructure alerts applicable to all application services in the 
service_registry

### Expected pattern
This plugin will create alert policy for all application services in the service registry. The name of each policy will
be in the format of env-service and will be created for all environments in the config.env_notification_map

### Service registry
config.conditions defines the alert conditions as well as the default threshold levels. However, these default values 
can be overwritten at the service level within the service_registry. To do so, create an "alerts" key in the service's
entry, then create a key for the alert condition you are attempting to modify. Then enter the condition key + new value.

##### Example service overwriting the cpu default thresholds:
```
"myservice": {
  "type": "http_service",
  "description": "Example service",
  "repository": "github.com/org/myservice",
  "jira_project": "example",
  "chef_role": "example",
  "environments": ["prod", "staging", "proto", "alpha"],
  "policies": ["global_buckets_ro", "instance_introspection"],
  "alerts": {
    "replica_lag": {
      "critical_threshold": {
        "value": 40
      }
    },
    "cpu_percent": {
        "enabled": false
    }
  }
}
```