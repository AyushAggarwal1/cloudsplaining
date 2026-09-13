# Creating an Exclusions File

As mentioned previously, Cloudsplaining tool does not attempt to understand the context behind everything in your AWS account. It's possible to understand the context behind some of these things programmatically - whether the policy is applied to an instance profile, whether the policy is attached, whether inline IAM policies are in use, and whether or not AWS Managed Policies are in use. **Only you know the context behind the design of your AWS infrastructure and the IAM strategy**.

As such, it's important to eliminate False Positives that are context-dependent. You can do this with an exclusions file. We've included a command that will generate an exclusions file for you so you don't have to remember the required format.

You can create an exclusions template via the following command:

```bash
cloudsplaining create-exclusions-file
```

This will generate a file in your current directory titled `exclusions.yml`.

> **Note:** AWS service-linked roles (those under the `/aws-service-role/` path, named `AWSServiceRoleFor...`) are always excluded, regardless of the exclusions file. AWS owns their permissions and trust policies, so nothing about them is evaluated. They still appear in the report and in the results JSON with `is_excluded: true`, so the role total matches your account, and the scan prints a one-line summary of how many were excluded.

Now when you run the `scan` command, you can use the exclusions file like this:

```bash
cloudsplaining scan --exclusions-file exclusions.yml --input-file examples/files/example.json --output examples/files/
```
