# IAM Secret Rotator

While Secrets Manager is often employed by best practices to maintain access to secrets due to its ability to auto-rotate secrets in AWS, maintaining high-availability and operating these changes at scale demands a programatic approach.
Be weary that the use of Secrets Manager even for testing purposes will incur some charges. 

## Solution Architecture 

![iam-key-rotator](https://github.com/user-attachments/assets/266cb7ba-24e9-4b8a-a2f9-f6dc61623813)

## Lambda Function

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

## CDK 

AWS CDK stack automates IAM access key rotation by deploying the AWS Lambda function, IAM role, and supporting AWS resources for secure key management. 

The stack uses L2 constructs and includes AWS SES for email notifications and AWS SNS for failure alerts.

Important: the values are hardcoded with my e-mail address for testing purposes. 

TODO: refine role best access for Lambda, had to give IAMFullAccess to test every other thing more efficiently. 

### SES Configuration:

* Configures AWS Simple Email Service (SES) to verify the source email and notification recipient.

* Ensures emails can be sent securely from an approved sender.

### SNS Configuration:

* Creates an SNS topic to handle failure alerts.

* Subscribes an administrator’s email for instant notifications in case of key rotation failures.

### IAM Role for Lambda Execution:

* Grants Lambda permissions to manage IAM access keys and read/write from AWS Secrets Manager.

* Includes inline policies for sending emails via SES and publishing messages to SNS.

### Lambda Function for Key Rotation:

* Deploys a Python-based AWS Lambda function to automate the IAM key rotation process.

* Configured with environment variables to reference the SNS topic and SES source email.

* Has a timeout of 30 seconds for efficient execution.

### Secrets Manager Integration:

* Creates and stores IAM access keys in AWS Secrets Manager.

* Adds a rotation schedule that automatically triggers the Lambda function every 90 days.

* Ensures previous keys are securely retired while new keys are validated and activated.

