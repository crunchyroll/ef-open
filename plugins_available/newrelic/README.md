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

### Quick steps to adding new alert conditions to config.py
1. Create an alert condition in the newrelic ui
2. browse to the alert metric (manage button from the alert policy view)
3. Copy the alert condition id from the url bar. In the example below, the id is "678910"
	For example: https://infrastructure.newrelic.com/accounts/1234567/settings/alerts/678910
4. Retrieve the condition object from the newrelic api:
	curl -sX GET --header "X-Api-Key: API_KEY"  "https://infra-api.newrelic.com/v2/alerts/conditions/565433" | jq .data
5. add the cleaned up json condition object to alert_conditions in the config.py file. the key is the name of the alert condition, and the value should be the condition object. make sure the key and the objects "name" value match. 
6. delete the following keys from the condition object: "id", "created_at_epoch_millis", "updated_at_epoch_millis"
7. update dynamic values to variables. The variables available are {{ENV}}, {{SERVICE}}, and {{POLICY_ID}}. One value that will certainly need to be changed is "policy_id". Typically filter values will use these variables as well. 
8. Change the "enabled" value to be a python boolean; True or False (note capitalization)
