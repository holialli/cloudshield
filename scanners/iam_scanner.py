"""IAM posture scanner for CloudShield."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError


@dataclass
class Finding:
    service: str
    resource_id: str
    title: str
    description: str
    severity: str
    cis_control: str
    remediation: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IAMScanner:
    """Scan IAM for CIS AWS Foundations issues."""

    def __init__(self, session: boto3.Session) -> None:
        self.iam = session.client("iam")

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._scan_root_mfa())
        findings.extend(self._scan_access_key_age())
        findings.extend(self._scan_wildcard_policies())
        return findings

    def _scan_root_mfa(self) -> List[Finding]:
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
        except (BotoCoreError, ClientError) as exc:
            return [
                Finding(
                    service="iam",
                    resource_id="root-account",
                    title="Unable to evaluate root MFA status",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 1.2",
                    remediation="Verify AWS account-level MFA status manually.",
                    details={"error": str(exc)},
                )
            ]

        if summary.get("AccountMFAEnabled", 0) == 1:
            return []

        return [
            Finding(
                service="iam",
                resource_id="root-account",
                title="Root account MFA is disabled",
                description="The AWS root account does not have MFA enabled.",
                severity="High",
                cis_control="CIS 1.2",
                remediation="Enable MFA on the root account immediately.",
                details={"account_mfa_enabled": False},
            )
        ]

    def _scan_access_key_age(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            users = self.iam.list_users().get("Users", [])
        except (BotoCoreError, ClientError) as exc:
            return [
                Finding(
                    service="iam",
                    resource_id="iam-users",
                    title="Unable to list IAM users",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 1.14",
                    remediation="Review IAM permissions and connectivity.",
                    details={"error": str(exc)},
                )
            ]

        now = datetime.now(timezone.utc)
        for user in users:
            user_name = user["UserName"]
            try:
                access_keys = self.iam.list_access_keys(UserName=user_name).get(
                    "AccessKeyMetadata", []
                )
            except (BotoCoreError, ClientError) as exc:
                findings.append(
                    Finding(
                        service="iam",
                        resource_id=user_name,
                        title="Unable to evaluate IAM access key age",
                        description=str(exc),
                        severity="Low",
                        cis_control="CIS 1.14",
                        remediation="Review the IAM user manually.",
                        details={"error": str(exc), "user": user_name},
                    )
                )
                continue

            for access_key in access_keys:
                create_date = access_key["CreateDate"]
                age_days = (now - create_date).days
                if age_days <= 90:
                    continue

                findings.append(
                    Finding(
                        service="iam",
                        resource_id=f"{user_name}:{access_key['AccessKeyId']}",
                        title="IAM access key older than 90 days",
                        description=(
                            f"Access key for user {user_name} is {age_days} days old."
                        ),
                        severity="Medium",
                        cis_control="CIS 1.14",
                        remediation="Rotate the access key and remove unused keys.",
                        details={
                            "user": user_name,
                            "access_key_id": access_key["AccessKeyId"],
                            "age_days": age_days,
                            "status": access_key.get("Status"),
                        },
                    )
                )

        return findings

    def _scan_wildcard_policies(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            policies = self.iam.list_policies(Scope="Local", OnlyAttached=False).get(
                "Policies", []
            )
        except (BotoCoreError, ClientError) as exc:
            return [
                Finding(
                    service="iam",
                    resource_id="iam-policies",
                    title="Unable to list IAM policies",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 1.16",
                    remediation="Review IAM policy visibility and permissions.",
                    details={"error": str(exc)},
                )
            ]

        for policy in policies:
            policy_arn = policy["Arn"]
            policy_name = policy["PolicyName"]
            try:
                versions = self.iam.list_policy_versions(PolicyArn=policy_arn)[
                    "Versions"
                ]
                default_version_id = next(
                    version["VersionId"]
                    for version in versions
                    if version["IsDefaultVersion"]
                )
                document = self.iam.get_policy_version(
                    PolicyArn=policy_arn, VersionId=default_version_id
                )["PolicyVersion"]["Document"]
            except (BotoCoreError, ClientError, StopIteration) as exc:
                findings.append(
                    Finding(
                        service="iam",
                        resource_id=policy_arn,
                        title="Unable to inspect IAM policy document",
                        description=str(exc),
                        severity="Low",
                        cis_control="CIS 1.16",
                        remediation="Review the IAM policy manually.",
                        details={"policy_arn": policy_arn, "error": str(exc)},
                    )
                )
                continue

            if self._contains_wildcard_permissions(document):
                findings.append(
                    Finding(
                        service="iam",
                        resource_id=policy_arn,
                        title="IAM policy contains wildcard permissions",
                        description=(
                            f"Policy {policy_name} uses wildcard actions or resources."
                        ),
                        severity="High",
                        cis_control="CIS 1.16",
                        remediation="Replace wildcard permissions with scoped IAM actions and resources.",
                        details={"policy_name": policy_name, "policy_arn": policy_arn},
                    )
                )

        return findings

    @staticmethod
    def _contains_wildcard_permissions(document: Dict[str, Any]) -> bool:
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            action = statement.get("Action")
            resource = statement.get("Resource")
            if action == "*" or resource == "*":
                return True
            if isinstance(action, list) and any(item == "*" for item in action):
                return True
            if isinstance(resource, list) and any(item == "*" for item in resource):
                return True
        return False
