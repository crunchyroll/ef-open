### Purpose 
Automate the creation of baseline NewRelic ec2 infrastructure alerts applicable to all application services in the 
service_registry

### Expected pattern
This plugin will create _service_ and _service-warn_ alert policies in NewRelic for all applications in the
service_registry. These alert policies will contain infrastructure alert conditions which target ec2 instances created 
and tagged by ef-cf. 

### Api Token
The encrypted_token config value should be a NewRelic admin token encrypted by KMS. Any AWS accounts with environments
in  config.alert_environments will need decrypt privileges to this key. 

### Current restrictions
Currently only infrastructure alerts are supported by this plugin (ie. metrics viewable in 
https://infrastructure.newrelic.com). If additional alert condition types are required (apdex, synthetic transactions, 
etc.) this functionality can be extended. 

### Service registry
config.conditions defines the alert conditions as well as the default threshold levels. However, these default values 
can be overwritten at the service level within the service_registry. To do so, create an "alerts" key in the service's
entry, then set new values for {{alert}}_warning and/or {{alert}}_critical. The alert names can be found in the "sr_name"
key in config.conditions. 

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
        "cpu_warning": 70,
        "cpu_critical": 75
      }
    }
  }
```