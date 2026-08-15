# CloudShield

CloudShield is a modular Python CSPM tool for AWS posture checks and targeted remediation.

**Scanning is read-only.** Nothing in the target account is modified unless you pass both `--remediate` and `--allow`.

## What It Scans

**IAM** (global)
- Root account MFA (CIS 1.5)
- Access key age over 90 days, with inactive keys graded lower (CIS 1.14)
- Over-permissive policies on customer-managed policies, roles, users and groups (CIS 1.16)

**S3** (global, per-bucket calls routed to each bucket's own region)
- Account-level and bucket-level Public Access Block
- Public bucket ACLs and public bucket policies

**EC2** (per region)
- Security groups exposing SSH/RDP to the internet, by port *range* containment
- Security groups allowing all protocols from the internet
- Default security group not empty (CIS 5.4)
- IMDSv2 enforcement (CIS 5.6)
- EBS encryption by default, and encryption of attached volumes (CIS 2.2.1)
- Instances with public IPs (FSBP EC2.9)

Policy analysis grades what it finds: `Allow *:*` is High, a service wildcard like `s3:*`, a bare `Resource: "*"`, a `NotAction` grant, or an admin grant narrowed by a `Condition` are Medium. `Deny` statements are never findings — they are guardrails. AWS service-linked roles are recorded as `EXCEPTION` rather than failures.

## Requirements

- Python 3.10+
- AWS credentials via instance profile, environment, or the local profile chain
- Read-only audit permissions (`SecurityAudit` covers the scan; remediation needs write permissions for the specific checks you allow)

## Install

```bash
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env`, or use environment variables:

| Variable | Purpose |
| --- | --- |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Session region, and the default region scanned |
| `AWS_ROLE_ARN` | Optional audit role to assume via STS |
| `AWS_EXTERNAL_ID` | External ID for the assume-role call |
| `AWS_ROLE_SESSION_NAME` | Session name (default `CloudShieldSession`) |
| `CLOUDSHIELD_REPORT_PATH` | Default PDF path |
| `CLOUDSHIELD_RESULTS_PATH` | Default JSON path |

When `AWS_ROLE_ARN` is set, the session carries *refreshable* credentials, so a long multi-region scan does not die at the one-hour assume-role expiry.

## Run

```bash
# Scan the session region
python main.py

# Scan specific regions, or every region enabled for the account
python main.py --regions us-east-1 eu-west-1
python main.py --regions all

# Gate a pipeline
python main.py --fail-on high
python main.py --min-score 80
```

Outputs a PDF report and a JSON results file. Exit codes: `0` clean, `1` a gate was breached, `2` the scan could not run.

### Remediation

Remediation is opt-in twice: `--remediate` says execute rather than plan, and `--allow` says which checks you are authorising.

```bash
# See what could be fixed (nothing is changed)
python main.py

# List the checks that have an automated fix
python remediate.py --list-checks

# Apply one specific check
python main.py --remediate --allow S3-PUBLIC-ACCESS-BLOCK

# Or remediate later from a saved results file
python remediate.py --results cloudshield_results.json --fix --allow EC2-IMDSV2-REQUIRED
```

Automated fixes: bucket and account Public Access Block, EBS encryption by default, IMDSv2 enforcement, revoking risky security group ingress, emptying the default security group, deactivating stale access keys. Actions marked `[destructive]` can break a working workload — revoking ingress, disabling a credential, or blocking a bucket that intentionally serves public content.

Everything runs through boto3. No resource identifier is ever interpolated into a shell command.

### Suppressions

Record accepted risk in `cloudshield-suppressions.yaml` (see `cloudshield-suppressions.example.yaml`):

```yaml
suppressions:
  - check_id: EC2-NO-PUBLIC-IP
    resource_id: i-0123456789abcdef0
    reason: Public bastion, SSH restricted to the VPN CIDR.
    expires: 2026-12-31
```

Suppressed checks still appear in the report, marked `SUPPRESSED`. They do not affect the risk score and do not fail `--fail-on`. Expired entries are reported as warnings instead of being honoured.

## GitHub Actions Integration

```yaml
name: CloudShield Compliance

on:
  schedule:
    - cron: '0 8 * * *'
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - run: pip install -r requirements.txt

      - name: Run CloudShield
        env:
          AWS_REGION: us-east-1
          AWS_ROLE_ARN: ${{ secrets.CLOUDSHIELD_ROLE_ARN }}
        run: python main.py --regions all --fail-on high

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cloudshield-report
          path: |
            cloudshield_report.pdf
            cloudshield_results.json
```

`--fail-on high` makes the job fail the build on a High-severity finding. Use `if: always()` on the upload so the report survives a failed gate.

## Notes

- The PDF includes a Security Risk Score from 0 to 100. Repeated failures of the same check are discounted and capped, so one bad control across hundreds of resources cannot zero the score on its own.
- `cloudshield_report.pdf` and `cloudshield_results.json` contain real account IDs, ARNs and resource names. They are gitignored.
