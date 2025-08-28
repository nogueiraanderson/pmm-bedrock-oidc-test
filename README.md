# PMM Bedrock OIDC Test

This repository tests the OIDC (OpenID Connect) integration between GitHub Actions and AWS Bedrock for the PMM project.

## Purpose

Demonstrate secure, credential-less authentication from GitHub Actions to AWS services using OIDC federation to access Claude models on Amazon Bedrock.

## Architecture

```
GitHub Actions → OIDC Token → AWS STS → Temporary Credentials → Amazon Bedrock
```

## AWS Configuration

### OIDC Provider
- **URL**: `https://token.actions.githubusercontent.com`
- **Audience**: `sts.amazonaws.com`

### IAM Role
- **Name**: `pmm-claude-bedrock-github-actions`
- **ARN**: `arn:aws:iam::119175775298:role/pmm-claude-bedrock-github-actions`
- **Trust Policy**: Allows GitHub Actions from this repo to assume the role

### Permissions
- Access to Claude models on Amazon Bedrock
- CloudWatch metrics for monitoring

## GitHub Secrets Required

- `AWS_ROLE_ARN`: The ARN of the IAM role to assume
- `AWS_REGION`: The AWS region (us-east-2)

## Testing

The `.github/workflows/test-oidc.yml` workflow tests the OIDC authentication by:
1. Requesting an OIDC token from GitHub
2. Exchanging it for AWS credentials via STS
3. Calling AWS services to verify access

## Security

- No AWS credentials stored in GitHub
- Short-lived tokens (1 hour max)
- Scoped to specific repositories
- Full audit trail in CloudTrail

## Related Repositories

- [percona/pmm](https://github.com/percona/pmm) - Main PMM repository
- [percona/pmm-qa](https://github.com/percona/pmm-qa) - PMM QA repository