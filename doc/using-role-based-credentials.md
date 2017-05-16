How to get and use role-based instance credentials for AWS access for your service
 Edit  Save for later  Watching  Share
Pages  DevOps  ETP Services and Runbooks
Skip to end of banner
1 JIRA link
Go to start of banner
Skip to end of metadata
Created by Jim Youll, last modified on Jul 14, 2016 Go to start of metadata
Use case
"My service needs access to S3, or other AWS resources, via the AWS API."
To do this, the service needs credentials.
Those credentials are available to the service by querying a special HTTP endpoint available to the service, that will give it the /role credentials/ for that instance in that service.
Role credentials are managed by AWS, and rotated every several hours, so they can't just be read at service startup, but must be replaced by the running service from time to time.
All instances and lambdas in the new environments will be in roles by definition. All instances and lambdas should always be in roles. 
Not all instances in the current "dev" environment in AWS are in roles. That's incorrect. We must transition away from using "user" accounts for services to make our services production-ready as we get ready to go into production.
Services will not be given "user" credentials in the new staging, proto, and prod environments. As we phase in the "Staging" environment for Alpha2 and beyond, services will break if they rely on hard-coded AWS credentials for AWS API calls rather than reading credentials dynamically from AWS.
To get the instance's credentials from the enviroment is somewhat easier than doing it any other way, because it is a simple HTTP lookup.
Query the instance metadata endpoint with a simple HTTP request; the response is a JSON blob containing credentials. Use the credentials to create AWS API requests.
It is also possible to look up the instance's role, so you don't have to hard-code the role name. This is useful in the event that the service should change its name, the code will be more resilient. Additionally, role names are environment-dependent, so it is best to look up the role name first (this can be done once at instance startup), and then construct a credential query as shown in the example below.
Example
The simple example below shows use of curl to make the same HTTP requests that application code would make for a service.
AccessKeyId and SecretAccessKey in the response below are used exactly as you would use these same items from a user account.
Expiration: is the UTC time at which the credentials will expire. (that's 19:37:58 PDT)
 
# get role and environment (in this example, environment is "staging"; role is "vod-origin")
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
staging-vod-origin
  
# get credentials
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/staging-vod-origin/
{
  "Code" : "Success",
  "LastUpdated" : "2016-05-26T20:21:16Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAIUOIIPV5MK27ZEEQ",
  "SecretAccessKey" : "xHPuOc0wOCJXXXXXXXQSj8U5XXXXXXXXoke6XXXX",
  "Token" : "FQoDYXdzEJX//////////wEaDD68M++E6h0XXXXXXXXXXw6lC0XgY5j2MyzSzxV2OOY29qjUlIUInEGyW1fIj1oTVhf/2hkuliDseKjMiyqEph9catduCOXFaWynY2ybuNTWDEe/84NINbycdynoZTT7y8uZzkOmf/bT2nOtYHOadM051UenANz9yFmW2ljds0HEcCD/xJn4+XXXXXXXXXXXXrJfCx2r/utsOsYDpSosQ0oESkFXyj82fOZdtZ4c0laZqJGiNd/mizdrT01RkGYDw0f80NmpzIlrDSdXgKS5CsPTvifwA3LTcuLZQHC8UcZIsQrotgudfFx825BOHs7mQs8Nbki/EXXXXXXXWPs0tqH6SowQ729MaEpoT+GWrUPHrCk8ZdM3MvmRIh1sfEcowLWdugU=",
  "Expiration" : "2016-05-27T02:37:58Z"
}
 
Here's Amazon's page saying effectively the same thing: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
Also see the FAQS: https://aws.amazon.com/iam/faqs/
With some services, specifically S3, you can use the Token inside a request header to make a request, which saves you the trouble of signing a request to S3
Q: How can I use temporary security credentials to call AWS service APIs?
If you're making direct HTTPS API requests to AWS, you can sign those requests with the temporary security credentials that you get from AWS Security Token Service (AWS STS). To do this, do the following:
Use the access key ID and secret access key that are provided with the temporary security credentials the same way you would use long-term credentials to sign a request. For more information about signing HTTPS API requests, see Signing AWS API Requests in the AWS General Reference.
 Use the session token that is provided with the temporary security credentials. Include the session token in the "x-amz-security-token" header. See the following example request
 For Amazon S3, via the "x-amz- security-token" HTTP header. 
 For other AWS services, via the SecurityToken paramete

Token Expiration
Q: How do I rotate the temporary security credentials on the EC2 instance?
The AWS temporary security credentials associated with an IAM role are automatically rotated multiple times a day. 
New temporary security credentials are made available no later than five minutes before the existing temporary security credentials expire.

Services must have a strategy to deal with the rotation of these credentials, which is carried out behind the scenes by AWS.
Some options:
polling every several minutes (AWS says there's at least 5 minutes advance availability of the new key before expiration)
set a timer to fire 1-4 minutes before expiration (to allow for slight clock skew between AWS and you). The credentials have expiration timestamps on them, so when you retrieve a credential, you also know when it will expire.
treat the credential you have like a cache, and query for a new one when it fails, then retry the operation that failed -- probably the least good strategy
persist the expiration time, and always check it before using the credential. If "now" is later than "expiration time -1 minute", fetch a new credential before making the API call.

The thing NOT to /not/ do (if you can help it) is to request the credential every time you need it. The calls to the meta-data endpoint are REALLY CHEAP but they aren't free. However, this is a survivable strategy for the near term, and into the future, because the calls to the HTTP endpoint are pretty cheap. Developers may find that string parsing to extract the credential from the returned (small) blob is more expensive than the local http call itself. Jim Youll measured response times for fetching the credential on a t2.small instance using curl (lots of overhead) and attained about 250 reads/sec sustained.
