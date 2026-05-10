# AWS Read-All and Billing Setup Guide

This guide explains how to create an AWS IAM User (or Role) that has the capacity to discover all tenant resources, read their properties and data, and access usage and cost statistics. 

This account is strictly read-only and cannot write, create, or change any resources.

## Step 1: Enable IAM Access to Billing (Requires Root/Admin)
By default, AWS blocks IAM users from seeing billing and cost data, even if they have the correct IAM permissions. You must enable this at the root account level first.

1. Log into the AWS Management Console using your **Root account** (or an Admin account with permissions to modify account settings).
2. Click on your account name in the top right corner and select **Account**.
3. Scroll down to the **IAM User and Role Access to Billing Information** section.
4. Click **Edit**, check the box for **Activate IAM Access**, and click **Update**.

## Step 2: Create the IAM User
1. Go to the **IAM (Identity and Access Management)** dashboard in the AWS Console.
2. In the left navigation pane, click **Users**, then click **Create user**.
3. Give the user a descriptive name (e.g., `ResourceAndCostAuditor`).
4. *Do not* check the box for "Provide user access to the AWS Management Console" (since you only want an API key for programmatic access).
5. Click **Next**.

## Step 3: Attach the Read-Only Policies
On the "Set permissions" page:
1. Select **Attach policies directly**.
2. In the search box, search for and check the following two AWS Managed Policies:
   * **`ReadOnlyAccess`**: This is a comprehensive AWS-managed policy that grants read-only permissions (List, Describe, Get) to virtually *all* AWS services and resources (EC2, S3, RDS, Lambda, etc.). It explicitly does not allow any `Put`, `Post`, `Update`, or `Delete` actions. It also allows reading data inside resources (e.g., downloading an S3 object).
   * **`AWSBillingReadOnlyAccess`**: This grants read-only access to the Billing console, Cost Explorer, Budgets, and usage reports.
3. Click **Next**, review the configuration, and click **Create user**.

## Step 4: Generate the API Key (Access Keys)
1. Once the user is created, click on the user's name (`ResourceAndCostAuditor`) in the IAM Users list.
2. Go to the **Security credentials** tab.
3. Scroll down to the **Access keys** section and click **Create access key**.
4. Select **Third-party service** or **Application running outside AWS**.
5. Click **Next**, optionally add a description tag, and click **Create access key**.
6. **IMPORTANT:** Copy the **Access Key ID** and the **Secret Access Key** immediately. This is the only time AWS will show you the Secret Access Key. These act as your API credentials.

## ⚠️ Important Considerations

* **Cost Explorer API Pricing:** While reading resource properties (like listing EC2 instances or S3 buckets) is generally free, **the AWS Cost Explorer API charges $0.01 per API request**. If you are building a script that polls cost data, ensure you cache the results and don't poll it every minute to avoid a large AWS bill.
* **Security Best Practice:** If the application that will use these API keys is hosted *inside* AWS (like on an EC2 instance, ECS container, or Lambda function), **do not create an IAM User/API Key**. Instead, create an **IAM Role** with those exact same two policies, and attach the Role directly to your compute resource. This avoids having long-lived API keys that could be leaked.
