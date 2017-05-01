## What it does, in one sentence
This is a collection of "Design Patterns" for AWS.

## See also
Name Patterns and Paths - for all the patterns for all the names we use (and derive) in the AWS environment.

### Least privilege is a firm, universal requirement
- Assign only the minimum-necessary set of privileges to services (via policies on IAM Roles, and policy statements on resources) and people (via policies on IAM Groups, and policy statements on resources).
- This is a core requirement, so it's policy by decree.
- For justification and background, see [Wikipedia: Principle of least privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege).

### Queue message generators and consumers
- Message generators and message consumers must be separate processes running in separate roles.
    Compliance with the least-privilege policy: 
  - Work creators (which write messages into queues) and work consumers (which read and operate on messages in queues) nearly always interact with some external service (database, S3, other services, ...) and nearly always need disparate privileges with those external services. 
  - Access rights for a service come from the role under which the service runs.
  - Role privileges are granted to instance or Lambdas.
  - Therefore, role privileges are a property of an instance, so different processes must run on different instances, each with the minimum necessary privileges.
  - Minimally, the differences between a message generator and consumer are
    - Generator: can create new messages in a queue
    - Consumer: can read and delete messages in a queue
- Scaling
  - A work creator and consumer will have different load profiles and needs. For example, a single work generator reading a database and creating message for consumers may be able to generate work much faster than a single consumer can process that work. We need to be able to scale consumer nodes separately from generators. Also, it's sometimes the case that a work-generator can only run as a single instance for simplicity, so scaling becomes complicated when the tasks are combined.
  - Separating work consumers and creators opens the possibility of a less-bursty, more-continuous model in which work generators aren't run as once-a-day crons, but continuously, or nearly so, generating many small batches of work throughout the day rather than single large batch once a day. This makes it possible to provision smaller (less expensive) workers that are nearly always busy, so there is no "savings" to combining workers on a single instance since the load will be flat and steady.
- Neatness
  - This pattern removes the possibility of a trivial feedback loop within a process that combines both reading and writing to the same queue.

