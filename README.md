# IAM Secret Rotator

While Secrets Manager is often employed by best practices to maintain access to secrets due to its ability to auto-rotate secrets in AWS, maintaining high-availability and operating these changes at scale demands a programatic approach. 

## Solution Architecture 

![iam-key-rotator](https://github.com/user-attachments/assets/266cb7ba-24e9-4b8a-a2f9-f6dc61623813)

## How secrets are rotated via Lambda

The Lambda function automates IAM access key rotation using AWS Secrets Manager with minimal downtime. 

### createSecret Stage:

* Generates a new IAM access key for the specified user.
* Stores the new key as an AWSPENDING version in AWS Secrets Manager.

### testSecret Stage:

* Retrieves the AWSPENDING secret and verifies its validity by attempting an IAM operation (listing access keys).
* If the test fails, the process stops, and an alert is sent via Amazon SNS.

### finishSecret Stage:

* Promotes the AWSPENDING version to AWSCURRENT.
* Moves the previous access key to AWSPREVIOUS.
* Disables and deletes the old IAM access key.
* Sends an email notification via Amazon SES to inform the user of the new credentials.

### error Handling & Notifications:

* all operations are wrapped in an error-handling decorator that logs failures and triggers SNS notifications for quick remediation.
