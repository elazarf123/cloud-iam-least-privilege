# Cloud IAM Least-Privilege Policy

An example AWS IAM identity policy that follows least privilege: it grants only the S3 actions a workload needs, on one bucket, and refuses unencrypted uploads.

The policy is in [`least-privilege-policy.json`](least-privilege-policy.json).

## What the policy does

| Statement | Effect | Actions | Resource | Why |
| :--- | :--- | :--- | :--- | :--- |
| `AllowSpecificReadAndWriteStorage` | Allow | `s3:GetObject`, `s3:PutObject`, `s3:ListBucket` | The `enterprise-audit-logs-bucket` bucket and its objects | Read, write, and list one bucket only |
| `DenyUnencryptedObjectUploads` | Deny | `s3:PutObject` | Objects in that bucket | Blocks any upload that doesn't request server-side encryption |

### Least-privilege choices

- **No wildcards.** Actions are listed individually instead of `s3:*`, and resources name one bucket instead of `*`.
- **Bucket vs. object ARNs.** `s3:ListBucket` applies to the bucket ARN (`arn:aws:s3:::bucket`), while `GetObject` and `PutObject` apply to object ARNs (`arn:aws:s3:::bucket/*`). Both are listed so each action has the resource type it needs.
- **No delete, no policy or ACL changes.** The workload can't remove data or change who has access.
- **Explicit deny for encryption.** The `Null` condition on `s3:x-amz-server-side-encryption` matches requests that don't include the encryption header, and an explicit deny overrides any allow elsewhere.

### What it compares against

A typical over-broad policy for the same workload:

```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}
```

That version would let the identity read, change, or delete every bucket in the account.

## How to use it

1. Replace `enterprise-audit-logs-bucket` with your bucket name.
2. Attach the policy to the IAM role or user the workload runs as.
3. Check it with IAM Access Analyzer's policy validation, or test specific actions with the IAM policy simulator.

## Notes

- If the bucket enforces default encryption, some uploads may succeed without the header at the bucket level, but this policy still denies them for this identity. Have clients send `x-amz-server-side-encryption` (for example `AES256` or `aws:kms`).
- If you use SSE-KMS, the identity also needs `kms:GenerateDataKey` and `kms:Decrypt` on the key.

## Roadmap

- A script that scans policies for wildcards and privilege-escalation actions such as `iam:PassRole`
- Equivalent examples for Azure RBAC and Google Cloud IAM
