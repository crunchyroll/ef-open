Setting up access to one or more AWS accounts
Request access
Decide in which AWS account(s) your personal account(s) should be created. These are our active accounts at present:
mysandbox : an AWS "dev environment": a place to experiment and try AWS features.
mynonprod : holds the staging and proto environments. Limited access. Two-factor authentication is required.
myprod : holds the production environment and other production resources. Extremely limited access. Only DevOps engineers have access to this account. Two-factor authentication is required.
myinternal : holds internal environment and other internal resources. Limited access. Two-factor authentication is required.

Install AWS Command Line tools
Full instructions at Installing the AWS Command Line Interface at AWS. If nothing has changed recently, just open a terminal window and do this:
$ curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
$ unzip awscli-bundle.zip
$ sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
To ensure you have the current version:
$ aws --version
$ sudo pip install --upgrade awscli
Log in and make credentials
After each account has been created, you will be given a temporary password.
For each new account:
Log in and change the password when prompted.
Your new password:
must not be the same as your old password
must be at least 8 characters long
must contain at least one symbol (!@#$%^&*()_+-=[]{}|')
must contain at least one number (0-9)
must contain at least one uppercase letter (A-Z)
must contain at least one lowercase letter (a-z)
Navigate to your personal account page in IAM (IAM / Users / your account name) or go directly there at a link like this:
https://console.aws.amazon.com/iam/home#users/<yourusername>
If there are credentials listed in the first section, "Access Keys" but you don't have those credentials stored in your .aws/credentials file and don't have a copy elsewhere, click Delete to remove them. Secrets can't be recovered after the fact, so access keys with lost secrets must be replaced. This is not a big deal.

If you don't have myinternal, mynonprod, myprod, mysandbox credentials in your .aws/credentials file (as per above, either because there aren't any on the account or because you just deleted some unknown credentails), click the Create Access Key button to generate an access key (ID + secret). Store the ID and secret in your .aws/credentials file in a profile matching the account name in .aws/credentials, as described below. Do this immediately. The secret cannot be retrieved later, once you go away from that page.
Set up your MFA device and enable two-factor authentication
Sign in and visit the Identity and Access Management (IAM) console at https://console.aws.amazon.com/iam/.
In the navigation pane, choose Users.
In the User Name list, choose your login name.
Choose the Security Credentials tab, and then choose the pencil beside Assigned MFA Device.

Select A virtual MFA device and hit Next Step
Run the Google Authenticator app on your mobile device:
pick the big red circle with the "+"
pick "Scan a barcode"
scan the barcode on the screen
On the AWS console:
provide two successive codes
hit Activate Virtual MFA
verify you see "The MFA device was successfully associated." 
In the upper-right corner of the AWS console, pick "Sign Out"

Log back in and verify you can use the services you expect
General instructions for setting up credentials files
For the first key (to create the credentials file)
Open a new terminal window, and set up a default one access key and secret using AWS command line tools
Running the command below will prompt for a key and secret, and will put them into the file ~/.aws/credentials
as the default account to be used by command line tools.
If you have access to multiple accounts, provide the key and secret for the 'mynonprod' account to be the default
profile used by AWS command line tools.

$ aws configure


Open the AWS credentials file at ~/.aws/credentials (Mac) or user/[Username]/.aws/credentials (Win) with an editor, and add the access key and secret for each of the accounts as shown below. (AWS documentation). You can have a [default] profile, but our tools don't expect one and we recommend you not set one up, so that you can be sure you're running a command in the correct account.
[myinternal]
aws_access_key_id = AKIA<whatever_for_myinternal>
aws_secret_access_key = <your_secret_key_for_myinternal>
[mynonprod]
aws_access_key_id = AKIA<whatever_for_mynonprod>
aws_secret_access_key = <your_secret_key_for_mynonprod>
[myprod]
aws_access_key_id = AKIA<whatever_for_myprod>
aws_secret_access_key = <your_secret_key_for_myprod>
[mysandbox]
aws_access_key_id = AKIA<whatever_for_mysandbox>
aws_secret_access_key = <your_secret_key_for_mysandbox>
 
Also modify the ~/.aws/config file to set defaults required for interacting with S3 SSE encryption from the AWS command line client
[profile myinternal]
s3 = signature_version = s3v4
[profile myprod]
s3 = signature_version = s3v4
[profile mynonprod]
s3 = signature_version = s3v4
[profile mysandbox]
s3 = signature_version = s3v4

### Testing credentials
A complete credentials file for an engineer with access to all environments including production would include "myinternal", "mynonprod", "myprod" and "mysandbox" sections.
These commands should run successfully for all environments and accounts you have access to.
```
$ aws ec2 describe-instances --region us-west-2 --profile myinternal
$ aws ec2 describe-instances --region us-west-2 --profile myprod
$ aws ec2 describe-instances --region us-west-2 --profile mynonprod
$ aws ec2 describe-instances --region us-west-2 --profile mysandbox
```

Security policy
If you have access to more than one AWS account, you must use a different password with each account.
If you have access to the "myprod" or "mynonprod" accounts, MFA 2-factor is required on every login.
