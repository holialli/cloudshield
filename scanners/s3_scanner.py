"""S3 posture scanner for CloudShield."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from core.awsutil import BOTO_CONFIG, error_code, is_access_denied
from core.models import (
    STATUS_FAIL,
    STATUS_INFO,
    STATUS_PASS,
    CheckResult,
    Finding,
    error_check,
)

PAB_FIELDS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

PUBLIC_ACL_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


class S3Scanner:
    """Scan S3 buckets for CIS AWS Foundations benchmark issues.

    ``ListBuckets`` is global, but every per-bucket call must go to the bucket's
    own region or AWS answers with ``PermanentRedirect`` /
    ``IllegalLocationConstraintException``. This scanner resolves each bucket's
    region and reuses a cached regional client.
    """

    service = "s3"

    def __init__(self, session: boto3.Session) -> None:
        self.session = session
        self.s3 = session.client("s3", config=BOTO_CONFIG)
        self.s3control = session.client("s3control", config=BOTO_CONFIG)
        self.sts = session.client("sts", config=BOTO_CONFIG)
        self._regional_clients: Dict[str, boto3.client] = {}

    def scan(self) -> List[Finding]:
        findings, _ = self.scan_detailed()
        return findings

    def scan_detailed(self) -> Tuple[List[Finding], List[CheckResult]]:
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
            return [], [
                error_check(
                    service="s3",
                    resource_id="s3-buckets",
                    resource_type="collection",
                    check_id="S3-LIST-BUCKETS",
                    check_name="S3 buckets can be listed",
                    message="Unable to list S3 buckets.",
                    error=exc,
                    cis_control="CIS 2.1",
                )
            ]

        checks.append(
            CheckResult(
                service="s3",
                resource_id="s3-buckets",
                resource_type="collection",
                check_id="S3-LIST-BUCKETS",
                check_name="S3 buckets can be listed",
                status=STATUS_PASS,
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
                    status=STATUS_INFO,
                    severity="Informational",
                    cis_control="CIS 2.1",
                    message="No S3 buckets found.",
                    details={"bucket_count": 0},
                )
            )
            return findings, checks

        for bucket in buckets:
            bucket_findings, bucket_checks = self._scan_bucket(bucket["Name"])
            findings.extend(bucket_findings)
            checks.extend(bucket_checks)
        return findings, checks

    # ------------------------------------------------------------------
    # Region resolution
    # ------------------------------------------------------------------

    def _bucket_region(self, bucket_name: str) -> str:
        try:
            location = self.s3.get_bucket_location(Bucket=bucket_name).get(
                "LocationConstraint"
            )
        except (BotoCoreError, ClientError):
            return self.session.region_name or "us-east-1"

        # us-east-1 is reported as None; the legacy "EU" alias means eu-west-1.
        if not location:
            return "us-east-1"
        if location == "EU":
            return "eu-west-1"
        return str(location)

    def _client_for(self, region: str) -> boto3.client:
        if region not in self._regional_clients:
            self._regional_clients[region] = self.session.client(
                "s3", region_name=region, config=BOTO_CONFIG
            )
        return self._regional_clients[region]

    def _get_account_id(self, checks: List[CheckResult]) -> Optional[str]:
        try:
            return self.sts.get_caller_identity().get("Account")
        except (BotoCoreError, ClientError) as exc:
            checks.append(
                error_check(
                    service="s3",
                    resource_id="account",
                    resource_type="account",
                    check_id="S3-ACCOUNT-ID",
                    check_name="Account identity available for account-level S3 checks",
                    message="Unable to resolve account identity for account-level S3 checks.",
                    error=exc,
                    cis_control="CIS 2.1",
                )
            )
            return None

    # ------------------------------------------------------------------
    # Account-level public access block
    # ------------------------------------------------------------------

    def _scan_account_public_access_block(
        self, account_id: str
    ) -> Tuple[List[Finding], List[CheckResult]]:
        resource_id = f"account:{account_id}"
        enabled = False
        configured = True

        try:
            config = self.s3control.get_public_access_block(AccountId=account_id).get(
                "PublicAccessBlockConfiguration", {}
            )
            enabled = all(config.get(field, False) for field in PAB_FIELDS)
        except (BotoCoreError, ClientError) as exc:
            # "Not configured" is a definitive FAIL, not an evaluation failure.
            # Only a genuine permissions/transport problem is an ERROR.
            if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                return [], [
                    error_check(
                        service="s3",
                        resource_id=resource_id,
                        resource_type="account",
                        check_id="S3-ACCOUNT-PUBLIC-ACCESS-BLOCK",
                        check_name="Account-level S3 Public Access Block is fully enabled",
                        message="Unable to evaluate account-level S3 Public Access Block.",
                        error=exc,
                        cis_control="CIS 2.1",
                        details={"account_id": account_id},
                    )
                ]
            configured = False

        details = {
            "account_id": account_id,
            "enabled": enabled,
            "configured": configured,
        }

        if enabled:
            return [], [
                CheckResult(
                    service="s3",
                    resource_id=resource_id,
                    resource_type="account",
                    check_id="S3-ACCOUNT-PUBLIC-ACCESS-BLOCK",
                    check_name="Account-level S3 Public Access Block is fully enabled",
                    status=STATUS_PASS,
                    severity="High",
                    cis_control="CIS 2.1",
                    message="Account-level S3 Public Access Block is fully enabled.",
                    details=details,
                )
            ]

        message = (
            "Account-level S3 Public Access Block is not configured."
            if not configured
            else "Account-level S3 Public Access Block is not fully enabled."
        )
        finding = Finding(
            service="s3",
            resource_id=resource_id,
            title="Account-level S3 Public Access Block is not fully enabled",
            description=message,
            severity="High",
            cis_control="CIS 2.1",
            remediation="Enable all account-level S3 Public Access Block controls.",
            details=details,
            check_id="S3-ACCOUNT-PUBLIC-ACCESS-BLOCK",
        )
        check = CheckResult(
            service="s3",
            resource_id=resource_id,
            resource_type="account",
            check_id="S3-ACCOUNT-PUBLIC-ACCESS-BLOCK",
            check_name="Account-level S3 Public Access Block is fully enabled",
            status=STATUS_FAIL,
            severity="High",
            cis_control="CIS 2.1",
            message=message,
            details=details,
        )
        return [finding], [check]

    # ------------------------------------------------------------------
    # Per-bucket checks
    # ------------------------------------------------------------------

    def _scan_bucket(self, bucket_name: str) -> Tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        region = self._bucket_region(bucket_name)
        client = self._client_for(region)

        public_acl = self._scan_bucket_acl(client, bucket_name, region, checks)
        public_policy = self._scan_bucket_policy(client, bucket_name, region, checks)
        pab_enabled = self._scan_bucket_pab(client, bucket_name, region, findings, checks)

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
                    region=region,
                    check_id="S3-BUCKET-PUBLIC",
                )
            )

        if pab_enabled is False:
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
                    region=region,
                    check_id="S3-PUBLIC-ACCESS-BLOCK",
                )
            )

        return findings, checks

    def _scan_bucket_acl(
        self, client, bucket_name: str, region: str, checks: List[CheckResult]
    ) -> bool:
        try:
            acl = client.get_bucket_acl(Bucket=bucket_name)
        except (BotoCoreError, ClientError) as exc:
            checks.append(
                error_check(
                    service="s3",
                    resource_id=bucket_name,
                    resource_type="bucket",
                    check_id="S3-BUCKET-ACL-PUBLIC",
                    check_name="S3 bucket ACL is not public",
                    message="Unable to evaluate bucket ACL.",
                    error=exc,
                    cis_control="CIS 2.1",
                    region=region,
                    details={"bucket": bucket_name},
                )
            )
            return False

        public_grantees = [
            grant.get("Grantee", {}).get("URI")
            for grant in acl.get("Grants", [])
            if grant.get("Grantee", {}).get("URI") in PUBLIC_ACL_GROUPS
        ]
        public_acl = bool(public_grantees)
        checks.append(
            CheckResult(
                service="s3",
                resource_id=bucket_name,
                resource_type="bucket",
                check_id="S3-BUCKET-ACL-PUBLIC",
                check_name="S3 bucket ACL is not public",
                status=STATUS_FAIL if public_acl else STATUS_PASS,
                severity="High",
                cis_control="CIS 2.1",
                message=(
                    "Bucket ACL grants public access."
                    if public_acl
                    else "Bucket ACL does not grant public access."
                ),
                details={
                    "bucket": bucket_name,
                    "public_acl": public_acl,
                    "public_grantees": public_grantees,
                },
                region=region,
            )
        )
        return public_acl

    def _scan_bucket_policy(
        self, client, bucket_name: str, region: str, checks: List[CheckResult]
    ) -> bool:
        try:
            status = client.get_bucket_policy_status(Bucket=bucket_name)
            public_policy = bool(status.get("PolicyStatus", {}).get("IsPublic", False))
        except (BotoCoreError, ClientError) as exc:
            # No policy at all is a pass, not an error.
            if error_code(exc) == "NoSuchBucketPolicy":
                public_policy = False
            else:
                checks.append(
                    error_check(
                        service="s3",
                        resource_id=bucket_name,
                        resource_type="bucket",
                        check_id="S3-BUCKET-POLICY-PUBLIC",
                        check_name="S3 bucket policy is not public",
                        message="Unable to evaluate bucket policy status.",
                        error=exc,
                        cis_control="CIS 2.1",
                        region=region,
                        details={"bucket": bucket_name},
                    )
                )
                return False

        checks.append(
            CheckResult(
                service="s3",
                resource_id=bucket_name,
                resource_type="bucket",
                check_id="S3-BUCKET-POLICY-PUBLIC",
                check_name="S3 bucket policy is not public",
                status=STATUS_FAIL if public_policy else STATUS_PASS,
                severity="High",
                cis_control="CIS 2.1",
                message=(
                    "Bucket policy is public."
                    if public_policy
                    else "Bucket policy is not public."
                ),
                details={"bucket": bucket_name, "public_policy": public_policy},
                region=region,
            )
        )
        return public_policy

    def _scan_bucket_pab(
        self,
        client,
        bucket_name: str,
        region: str,
        findings: List[Finding],
        checks: List[CheckResult],
    ) -> Optional[bool]:
        """Return True/False for the PAB state, or None when it is unknown."""

        try:
            config = client.get_public_access_block(Bucket=bucket_name).get(
                "PublicAccessBlockConfiguration", {}
            )
            enabled = all(config.get(field, False) for field in PAB_FIELDS)
            missing = [field for field in PAB_FIELDS if not config.get(field, False)]
        except (BotoCoreError, ClientError) as exc:
            code = error_code(exc)
            if code == "NoSuchPublicAccessBlockConfiguration":
                enabled, missing = False, list(PAB_FIELDS)
            else:
                # An AccessDenied here means we do not know the state. Reporting
                # it as a failure would be a false positive -- and would make the
                # remediator write to a bucket we never actually assessed.
                checks.append(
                    error_check(
                        service="s3",
                        resource_id=bucket_name,
                        resource_type="bucket",
                        check_id="S3-PUBLIC-ACCESS-BLOCK",
                        check_name="S3 bucket has full Public Access Block",
                        message=(
                            "Access denied reading bucket Public Access Block."
                            if is_access_denied(exc)
                            else "Unable to read bucket Public Access Block."
                        ),
                        error=exc,
                        cis_control="CIS 2.1",
                        region=region,
                        details={"bucket": bucket_name},
                    )
                )
                return None

        checks.append(
            CheckResult(
                service="s3",
                resource_id=bucket_name,
                resource_type="bucket",
                check_id="S3-PUBLIC-ACCESS-BLOCK",
                check_name="S3 bucket has full Public Access Block",
                status=STATUS_PASS if enabled else STATUS_FAIL,
                severity="High",
                cis_control="CIS 2.1",
                message=(
                    "All Public Access Block controls are enabled."
                    if enabled
                    else f"Public Access Block controls not enabled: {', '.join(missing)}."
                ),
                details={
                    "bucket": bucket_name,
                    "public_access_block_enabled": enabled,
                    "missing_controls": missing,
                },
                region=region,
            )
        )
        return enabled
