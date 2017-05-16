## What it does, in one sentence
This is a collection of "Design Patterns" for AWS.

## See also
Name Patterns and Paths - for all the patterns for all the names we use (and derive) in the AWS environment.

### Least privilege is a firm, universal requirement
- Assign only the minimum-necessary set of privileges
  - services: assign IAM Roles with policies on IAM Roles, and policy statements on resources
  - people: use IAM Group membership with policies on IAM Groups, and policy statements on resources
- This is a core requirement - policy by decree.
- For background, see [Wikipedia: Principle of least privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege).

### Queue message generators and consumers
- Message generators and message consumers must be separate processes running in separate roles in compliance with the least-privilege policy:
  - Work creators (which write messages into queues) and work consumers (which read and operate on messages in queues) nearly always interact with one or more external services (database, S3, ...). They also nearly always require disparate privileges on those external services.
  - Access rights are attached to the IAM Role under which the service (an EC2 instance or Lambda) runs.
  - Because Role privileges are held by an EC2 Instance or Lambda, services with different access needs must run on different EC2 instances or in separate Lambdas, each with the minimum necessary privileges for the service.
  - Minimally, the differences between a message generator and consumer are
    - Generator: can create new messages in a queue
    - Consumer: can read and delete messages in a queue
- Scaling
  - A work creator and consumer will have different load profiles and needs.
  - For example, a single work generator reading a database and creating message for consumers may be able to generate work much faster than a single consumer can process that work.
  - We scale consumer and generator nodes independently.
  - It's sometimes the case that a work-generator can only run on a single instance; scaling becomes complicated when the tasks are combined.
  - Separating work consumers and creators opens the possibility of a less-bursty, more-continuous model in which work generators aren't run like once-a-day crons, but continuously, or nearly so, generating many small batches of work steadily, rather than single large batches all at once. This makes it possible to provision smaller (less expensive) workers that are nearly always busy, and a load that is more predictable and steady.
- Neatness
  - This pattern removes the possibility of an accidental feedback loop that could occur when one process reads and writes the same queue.
