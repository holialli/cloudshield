"""S3 posture scanner for CloudShield."""

from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanners.iam_scanner import Finding


class S3Scanner:
    """Scan S3 buckets for CIS AWS Foundations benchmark issues."""

    def __init__(self, session: boto3.Session) -> None:
        self.s3 = session.client("s3")

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except (BotoCoreError, ClientError) as exc:
            return [
                Finding(
                    service="s3",
                    resource_id="s3-buckets",
                    title="Unable to list S3 buckets",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 2.1",
                    remediation="Review S3 permissions and API access.",
                    details={"error": str(exc)},
                )
            ]

        for bucket in buckets:
            bucket_name = bucket["Name"]
            findings.extend(self._scan_bucket(bucket_name))
        return findings

    def _scan_bucket(self, bucket_name: str) -> List[Finding]:
        findings: List[Finding] = []

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
        except (BotoCoreError, ClientError):
            pass

        try:
            policy_status = self.s3.get_bucket_policy_status(Bucket=bucket_name)
            public_policy = policy_status.get("PolicyStatus", {}).get("IsPublic", False)
        except (BotoCoreError, ClientError):
            pass

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

        return findings
