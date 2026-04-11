"""S3 posture scanner for CloudShield."""

from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanners.iam_scanner import CheckResult, Finding


class S3Scanner:
    """Scan S3 buckets for CIS AWS Foundations benchmark issues."""

    def __init__(self, session: boto3.Session) -> None:
        self.session = session
        self.s3 = session.client("s3")
        self.s3control = session.client("s3control")
        self.sts = session.client("sts")

    def scan(self) -> List[Finding]:
        findings, _ = self.scan_detailed()
        return findings

    def scan_detailed(self) -> tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        account_id = self._get_account_id(checks)
        if account_id:
            account_findings, account_checks = self._scan_account_public_access_block(account_id)
            findings.extend(account_findings)
            checks.extend(account_checks)

        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except (BotoCoreError, ClientError) as exc:
            finding = Finding(
                    service="s3",
                    resource_id="s3-buckets",
                    title="Unable to list S3 buckets",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 2.1",
                    remediation="Review S3 permissions and API access.",
                    details={"error": str(exc)},
                )
            check = CheckResult(
                service="s3",
                resource_id="s3-buckets",
                resource_type="collection",
                check_id="S3-LIST-BUCKETS",
                check_name="S3 buckets can be listed",
                status="ERROR",
                severity="Medium",
                cis_control="CIS 2.1",
                message="Unable to list S3 buckets.",
                details={"error": str(exc)},
            )
            return [finding], [check]

        checks.append(
            CheckResult(
                service="s3",
                resource_id="s3-buckets",
                resource_type="collection",
                check_id="S3-LIST-BUCKETS",
                check_name="S3 buckets can be listed",
                status="PASS",
                severity="Low",
                cis_control="CIS 2.1",
                message=f"S3 buckets listed successfully: {len(buckets)} bucket(s).",
                details={"bucket_count": len(buckets)},
            )
        )

        if not buckets:
            checks.append(
                CheckResult(
                    service="s3",
                    resource_id="s3-buckets",
                    resource_type="collection",
                    check_id="S3-NO-BUCKETS-FOUND",
                    check_name="S3 bucket inventory",
                    status="INFO",
                    severity="Informational",
                    cis_control="CIS 2.1",
                    message="No S3 Buckets Found.",
                    details={"bucket_count": 0},
                )
            )
            return findings, checks

        for bucket in buckets:
            bucket_name = bucket["Name"]
            bucket_findings, bucket_checks = self._scan_bucket(bucket_name)
            findings.extend(bucket_findings)
            checks.extend(bucket_checks)
        return findings, checks

    def _get_account_id(self, checks: List[CheckResult]) -> str | None:
        try:
            return self.sts.get_caller_identity().get("Account")
        except (BotoCoreError, ClientError) as exc:
            checks.append(
                CheckResult(
                    service="s3",
                    resource_id="account",
                    resource_type="account",
                    check_id="S3-ACCOUNT-ID",
                    check_name="Account identity available for account-level S3 checks",
                    status="ERROR",
                    severity="Medium",
                    cis_control="CIS 2.1",
                    message="Unable to resolve account identity for account-level S3 checks.",
                    details={"error": str(exc)},
                )
            )
            return None

    def _scan_account_public_access_block(
        self, account_id: str
    ) -> tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        try:
            response = self.s3control.get_public_access_block(AccountId=account_id)
            config = response.get("PublicAccessBlockConfiguration", {})
            enabled = all(
                config.get(field, False)
                for field in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
        except (BotoCoreError, ClientError) as exc:
            findings.append(
                Finding(
                    service="s3",
                    resource_id=f"account:{account_id}",
                    title="Unable to evaluate account-level S3 Public Access Block",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 2.1",
                    remediation="Verify s3control permissions and account-level public access settings.",
                    details={"account_id": account_id, "error": str(exc)},
                )
            )
            checks.append(
                CheckResult(
                    service="s3",
                    resource_id=f"account:{account_id}",
                    resource_type="account",
                    check_id="S3-ACCOUNT-PUBLIC-ACCESS-BLOCK",
                    check_name="Account-level S3 Public Access Block is fully enabled",
                    status="ERROR",
                    severity="Medium",
                    cis_control="CIS 2.1",
                    message="Unable to evaluate account-level S3 Public Access Block.",
                    details={"account_id": account_id, "error": str(exc)},
                )
            )
            return findings, checks

        if enabled:
            checks.append(
                CheckResult(
                    service="s3",
                    resource_id=f"account:{account_id}",
                    resource_type="account",
                    check_id="S3-ACCOUNT-PUBLIC-ACCESS-BLOCK",
                    check_name="Account-level S3 Public Access Block is fully enabled",
                    status="PASS",
                    severity="High",
                    cis_control="CIS 2.1",
                    message="Account-level S3 Public Access Block is fully enabled.",
                    details={"account_id": account_id, "enabled": True},
                )
            )
            return findings, checks

        findings.append(
            Finding(
                service="s3",
                resource_id=f"account:{account_id}",
                title="Account-level S3 Public Access Block is not fully enabled",
                description="One or more account-level S3 Public Access Block controls are disabled.",
                severity="High",
                cis_control="CIS 2.1",
                remediation="Enable all account-level S3 Public Access Block controls.",
                details={"account_id": account_id, "enabled": False},
            )
        )
        checks.append(
            CheckResult(
                service="s3",
                resource_id=f"account:{account_id}",
                resource_type="account",
                check_id="S3-ACCOUNT-PUBLIC-ACCESS-BLOCK",
                check_name="Account-level S3 Public Access Block is fully enabled",
                status="FAIL",
                severity="High",
                cis_control="CIS 2.1",
                message="Account-level S3 Public Access Block is not fully enabled.",
                details={"account_id": account_id, "enabled": False},
            )
        )
        return findings, checks

    def _scan_bucket(self, bucket_name: str) -> tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        public_acl = False
        public_policy = False
        public_access_block_enabled = False

        try:
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers") or grantee.get(
                    "URI", ""
                ).endswith("AuthenticatedUsers"):
                    public_acl = True
                    break
            checks.append(
                CheckResult(
                    service="s3",
                    resource_id=bucket_name,
                    resource_type="bucket",
                    check_id="S3-BUCKET-ACL-PUBLIC",
                    check_name="S3 bucket ACL is not public",
                    status="FAIL" if public_acl else "PASS",
                    severity="High",
                    cis_control="CIS 2.1",
                    message=(
                        "Bucket ACL grants public access."
                        if public_acl
                        else "Bucket ACL does not grant public access."
                    ),
                    details={"bucket": bucket_name, "public_acl": public_acl},
                )
            )
        except (BotoCoreError, ClientError):
            checks.append(
                CheckResult(
                    service="s3",
                    resource_id=bucket_name,
                    resource_type="bucket",
                    check_id="S3-BUCKET-ACL-PUBLIC",
                    check_name="S3 bucket ACL is not public",
                    status="ERROR",
                    severity="Medium",
                    cis_control="CIS 2.1",
                    message="Unable to evaluate bucket ACL.",
                    details={"bucket": bucket_name},
                )
            )

        try:
            policy_status = self.s3.get_bucket_policy_status(Bucket=bucket_name)
            public_policy = policy_status.get("PolicyStatus", {}).get("IsPublic", False)
            checks.append(
                CheckResult(
                    service="s3",
                    resource_id=bucket_name,
                    resource_type="bucket",
                    check_id="S3-BUCKET-POLICY-PUBLIC",
                    check_name="S3 bucket policy is not public",
                    status="FAIL" if public_policy else "PASS",
                    severity="High",
                    cis_control="CIS 2.1",
                    message=(
                        "Bucket policy is public."
                        if public_policy
                        else "Bucket policy is not public."
                    ),
                    details={"bucket": bucket_name, "public_policy": public_policy},
                )
            )
        except (BotoCoreError, ClientError):
            checks.append(
                CheckResult(
                    service="s3",
                    resource_id=bucket_name,
                    resource_type="bucket",
                    check_id="S3-BUCKET-POLICY-PUBLIC",
                    check_name="S3 bucket policy is not public",
                    status="ERROR",
                    severity="Medium",
                    cis_control="CIS 2.1",
                    message="Unable to evaluate bucket policy status.",
                    details={"bucket": bucket_name},
                )
            )

        try:
            public_access_block = self.s3.get_public_access_block(Bucket=bucket_name)
            config = public_access_block.get("PublicAccessBlockConfiguration", {})
            public_access_block_enabled = all(
                config.get(field, False)
                for field in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
        except (BotoCoreError, ClientError):
            public_access_block_enabled = False
            checks.append(
                CheckResult(
                    service="s3",
                    resource_id=bucket_name,
                    resource_type="bucket",
                    check_id="S3-PUBLIC-ACCESS-BLOCK",
                    check_name="S3 bucket has full Public Access Block",
                    status="FAIL",
                    severity="High",
                    cis_control="CIS 2.1",
                    message="Unable to confirm full Public Access Block; treated as disabled.",
                    details={"bucket": bucket_name, "public_access_block_enabled": False},
                )
            )

        if public_access_block_enabled:
            checks.append(
                CheckResult(
                    service="s3",
                    resource_id=bucket_name,
                    resource_type="bucket",
                    check_id="S3-PUBLIC-ACCESS-BLOCK",
                    check_name="S3 bucket has full Public Access Block",
                    status="PASS",
                    severity="High",
                    cis_control="CIS 2.1",
                    message="All Public Access Block controls are enabled.",
                    details={"bucket": bucket_name, "public_access_block_enabled": True},
                )
            )

        if public_acl or public_policy:
            findings.append(
                Finding(
                    service="s3",
                    resource_id=bucket_name,
                    title="S3 bucket is publicly accessible",
                    description="The bucket has a public ACL or public bucket policy.",
                    severity="High",
                    cis_control="CIS 2.1",
                    remediation="Remove public access and enable S3 Block Public Access.",
                    details={
                        "bucket": bucket_name,
                        "public_acl": public_acl,
                        "public_policy": public_policy,
                    },
                )
            )

        if not public_access_block_enabled:
            findings.append(
                Finding(
                    service="s3",
                    resource_id=bucket_name,
                    title="S3 bucket lacks full Public Access Block",
                    description="The bucket does not enforce all public access block settings.",
                    severity="High",
                    cis_control="CIS 2.1",
                    remediation="Enable S3 Public Access Block at the bucket level.",
                    details={"bucket": bucket_name, "public_access_block_enabled": False},
                )
            )

        return findings, checks
