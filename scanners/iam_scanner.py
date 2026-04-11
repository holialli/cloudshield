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


@dataclass
class CheckResult:
    service: str
    resource_id: str
    resource_type: str
    check_id: str
    check_name: str
    status: str
    severity: str
    cis_control: str
    message: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IAMScanner:
    """Scan IAM for CIS AWS Foundations issues."""

    def __init__(self, session: boto3.Session) -> None:
        self.iam = session.client("iam")

    def scan(self) -> List[Finding]:
        findings, _ = self.scan_detailed()
        return findings

    def scan_detailed(self) -> tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        root_findings, root_checks = self._scan_root_mfa()
        findings.extend(root_findings)
        checks.extend(root_checks)

        key_findings, key_checks = self._scan_access_key_age()
        findings.extend(key_findings)
        checks.extend(key_checks)

        policy_findings, policy_checks = self._scan_wildcard_policies()
        findings.extend(policy_findings)
        checks.extend(policy_checks)

        role_findings, role_checks = self._scan_role_access()
        findings.extend(role_findings)
        checks.extend(role_checks)

        return findings, checks

    def _scan_root_mfa(self) -> tuple[List[Finding], List[CheckResult]]:
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
        except (BotoCoreError, ClientError) as exc:
            finding = Finding(
                    service="iam",
                    resource_id="root-account",
                    title="Unable to evaluate root MFA status",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 1.2",
                    remediation="Verify AWS account-level MFA status manually.",
                    details={"error": str(exc)},
                )
            check = CheckResult(
                service="iam",
                resource_id="root-account",
                resource_type="account",
                check_id="IAM-ROOT-MFA",
                check_name="Root account MFA enabled",
                status="ERROR",
                severity="Medium",
                cis_control="CIS 1.2",
                message="Unable to evaluate root MFA status.",
                details={"error": str(exc)},
            )
            return [finding], [check]

        if summary.get("AccountMFAEnabled", 0) == 1:
            check = CheckResult(
                service="iam",
                resource_id="root-account",
                resource_type="account",
                check_id="IAM-ROOT-MFA",
                check_name="Root account MFA enabled",
                status="PASS",
                severity="High",
                cis_control="CIS 1.2",
                message="Root account MFA is enabled.",
                details={"account_mfa_enabled": True},
            )
            return [], [check]

        finding = Finding(
                service="iam",
                resource_id="root-account",
                title="Root account MFA is disabled",
                description="The AWS root account does not have MFA enabled.",
                severity="High",
                cis_control="CIS 1.2",
                remediation="Enable MFA on the root account immediately.",
                details={"account_mfa_enabled": False},
            )
        check = CheckResult(
            service="iam",
            resource_id="root-account",
            resource_type="account",
            check_id="IAM-ROOT-MFA",
            check_name="Root account MFA enabled",
            status="FAIL",
            severity="High",
            cis_control="CIS 1.2",
            message="Root account MFA is disabled.",
            details={"account_mfa_enabled": False},
        )
        return [finding], [check]

    def _scan_access_key_age(self) -> tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []
        try:
            users = self.iam.list_users().get("Users", [])
        except (BotoCoreError, ClientError) as exc:
            finding = Finding(
                    service="iam",
                    resource_id="iam-users",
                    title="Unable to list IAM users",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 1.14",
                    remediation="Review IAM permissions and connectivity.",
                    details={"error": str(exc)},
                )
            check = CheckResult(
                service="iam",
                resource_id="iam-users",
                resource_type="collection",
                check_id="IAM-USER-KEY-AGE",
                check_name="IAM user access keys rotated within 90 days",
                status="ERROR",
                severity="Medium",
                cis_control="CIS 1.14",
                message="Unable to list IAM users.",
                details={"error": str(exc)},
            )
            return [finding], [check]

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
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=user_name,
                        resource_type="user",
                        check_id="IAM-USER-KEY-AGE",
                        check_name="IAM user access keys rotated within 90 days",
                        status="ERROR",
                        severity="Low",
                        cis_control="CIS 1.14",
                        message="Unable to evaluate IAM access key age.",
                        details={"error": str(exc), "user": user_name},
                    )
                )
                continue

            if not access_keys:
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=user_name,
                        resource_type="user",
                        check_id="IAM-USER-KEY-AGE",
                        check_name="IAM user access keys rotated within 90 days",
                        status="PASS",
                        severity="Low",
                        cis_control="CIS 1.14",
                        message="User has no IAM access keys.",
                        details={"user": user_name},
                    )
                )
                continue

            for access_key in access_keys:
                create_date = access_key["CreateDate"]
                age_days = (now - create_date).days
                if age_days <= 90:
                    checks.append(
                        CheckResult(
                            service="iam",
                            resource_id=f"{user_name}:{access_key['AccessKeyId']}",
                            resource_type="access-key",
                            check_id="IAM-USER-KEY-AGE",
                            check_name="IAM user access keys rotated within 90 days",
                            status="PASS",
                            severity="Medium",
                            cis_control="CIS 1.14",
                            message="Access key age is within 90 days.",
                            details={
                                "user": user_name,
                                "access_key_id": access_key["AccessKeyId"],
                                "age_days": age_days,
                                "status": access_key.get("Status"),
                            },
                        )
                    )
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
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=f"{user_name}:{access_key['AccessKeyId']}",
                        resource_type="access-key",
                        check_id="IAM-USER-KEY-AGE",
                        check_name="IAM user access keys rotated within 90 days",
                        status="FAIL",
                        severity="Medium",
                        cis_control="CIS 1.14",
                        message=f"Access key is older than 90 days ({age_days} days).",
                        details={
                            "user": user_name,
                            "access_key_id": access_key["AccessKeyId"],
                            "age_days": age_days,
                            "status": access_key.get("Status"),
                        },
                    )
                )

        return findings, checks

    def _scan_wildcard_policies(self) -> tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []
        try:
            policies = self.iam.list_policies(Scope="Local", OnlyAttached=False).get(
                "Policies", []
            )
        except (BotoCoreError, ClientError) as exc:
            finding = Finding(
                    service="iam",
                    resource_id="iam-policies",
                    title="Unable to list IAM policies",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 1.16",
                    remediation="Review IAM policy visibility and permissions.",
                    details={"error": str(exc)},
                )
            check = CheckResult(
                service="iam",
                resource_id="iam-policies",
                resource_type="collection",
                check_id="IAM-POLICY-WILDCARD",
                check_name="IAM policy avoids wildcard action/resource",
                status="ERROR",
                severity="Medium",
                cis_control="CIS 1.16",
                message="Unable to list IAM policies.",
                details={"error": str(exc)},
            )
            return [finding], [check]

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
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=policy_arn,
                        resource_type="policy",
                        check_id="IAM-POLICY-WILDCARD",
                        check_name="IAM policy avoids wildcard action/resource",
                        status="ERROR",
                        severity="Low",
                        cis_control="CIS 1.16",
                        message="Unable to inspect IAM policy document.",
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
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=policy_arn,
                        resource_type="policy",
                        check_id="IAM-POLICY-WILDCARD",
                        check_name="IAM policy avoids wildcard action/resource",
                        status="FAIL",
                        severity="High",
                        cis_control="CIS 1.16",
                        message=f"Policy {policy_name} uses wildcard action/resource.",
                        details={"policy_name": policy_name, "policy_arn": policy_arn},
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=policy_arn,
                        resource_type="policy",
                        check_id="IAM-POLICY-WILDCARD",
                        check_name="IAM policy avoids wildcard action/resource",
                        status="PASS",
                        severity="High",
                        cis_control="CIS 1.16",
                        message=f"Policy {policy_name} is scoped without wildcard action/resource.",
                        details={"policy_name": policy_name, "policy_arn": policy_arn},
                    )
                )

        return findings, checks

    def _scan_role_access(self) -> tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        try:
            roles = self.iam.list_roles().get("Roles", [])
        except (BotoCoreError, ClientError) as exc:
            finding = Finding(
                service="iam",
                resource_id="iam-roles",
                title="Unable to list IAM roles",
                description=str(exc),
                severity="Medium",
                cis_control="CIS 1.16",
                remediation="Review IAM role permissions and API access.",
                details={"error": str(exc)},
            )
            check = CheckResult(
                service="iam",
                resource_id="iam-roles",
                resource_type="collection",
                check_id="IAM-ROLE-WILDCARD",
                check_name="IAM role access avoids wildcard action/resource",
                status="ERROR",
                severity="Medium",
                cis_control="CIS 1.16",
                message="Unable to list IAM roles.",
                details={"error": str(exc)},
            )
            return [finding], [check]

        for role in roles:
            role_name = role.get("RoleName", "unknown-role")
            role_arn = role.get("Arn", role_name)
            role_path = role.get("Path", "")
            service_linked_role = self._is_service_linked_role(role_name, role_arn, role_path)
            has_wildcard_permissions = False
            policy_sources: List[str] = []

            try:
                attached = self.iam.list_attached_role_policies(RoleName=role_name).get(
                    "AttachedPolicies", []
                )
            except (BotoCoreError, ClientError) as exc:
                findings.append(
                    Finding(
                        service="iam",
                        resource_id=role_arn,
                        title="Unable to inspect attached role policies",
                        description=str(exc),
                        severity="Low",
                        cis_control="CIS 1.16",
                        remediation="Review role permissions manually.",
                        details={"role_name": role_name, "error": str(exc)},
                    )
                )
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=role_arn,
                        resource_type="role",
                        check_id="IAM-ROLE-WILDCARD",
                        check_name="IAM role access avoids wildcard action/resource",
                        status="ERROR",
                        severity="Low",
                        cis_control="CIS 1.16",
                        message="Unable to inspect attached role policies.",
                        details={"role_name": role_name, "error": str(exc)},
                    )
                )
                continue

            for attached_policy in attached:
                policy_arn = attached_policy["PolicyArn"]
                policy_name = attached_policy["PolicyName"]
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
                except (BotoCoreError, ClientError, StopIteration):
                    continue

                if self._contains_wildcard_permissions(document):
                    has_wildcard_permissions = True
                    policy_sources.append(policy_name)

            try:
                inline_policies = self.iam.list_role_policies(RoleName=role_name).get(
                    "PolicyNames", []
                )
            except (BotoCoreError, ClientError):
                inline_policies = []

            for inline_policy_name in inline_policies:
                try:
                    inline_doc = self.iam.get_role_policy(
                        RoleName=role_name, PolicyName=inline_policy_name
                    )["PolicyDocument"]
                except (BotoCoreError, ClientError):
                    continue

                if self._contains_wildcard_permissions(inline_doc):
                    has_wildcard_permissions = True
                    policy_sources.append(f"inline:{inline_policy_name}")

            if has_wildcard_permissions and service_linked_role:
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=role_arn,
                        resource_type="role",
                        check_id="IAM-ROLE-WILDCARD",
                        check_name="IAM role access avoids wildcard action/resource",
                        status="EXCEPTION",
                        severity="Informational",
                        cis_control="CIS 1.16",
                        message="AWS-managed service-linked role uses wildcard access (exception).",
                        details={
                            "role_name": role_name,
                            "role_arn": role_arn,
                            "wildcard_policies": policy_sources,
                            "exception_type": "AWS-Managed Service-Linked Role",
                        },
                    )
                )
            elif has_wildcard_permissions:
                findings.append(
                    Finding(
                        service="iam",
                        resource_id=role_arn,
                        title="IAM role has wildcard access",
                        description=(
                            f"Role {role_name} has wildcard permissions in policy: {', '.join(policy_sources)}."
                        ),
                        severity="High",
                        cis_control="CIS 1.16",
                        remediation="Replace wildcard permissions with least-privilege scoped actions and resources.",
                        details={
                            "role_name": role_name,
                            "role_arn": role_arn,
                            "wildcard_policies": policy_sources,
                        },
                    )
                )
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=role_arn,
                        resource_type="role",
                        check_id="IAM-ROLE-WILDCARD",
                        check_name="IAM role access avoids wildcard action/resource",
                        status="FAIL",
                        severity="High",
                        cis_control="CIS 1.16",
                        message="Role has wildcard access in one or more policies.",
                        details={
                            "role_name": role_name,
                            "role_arn": role_arn,
                            "wildcard_policies": policy_sources,
                        },
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=role_arn,
                        resource_type="role",
                        check_id="IAM-ROLE-WILDCARD",
                        check_name="IAM role access avoids wildcard action/resource",
                        status="PASS",
                        severity="High",
                        cis_control="CIS 1.16",
                        message="Role policies are scoped without wildcard action/resource.",
                        details={"role_name": role_name, "role_arn": role_arn},
                    )
                )

        return findings, checks

    @staticmethod
    def _is_service_linked_role(role_name: str, role_arn: str, role_path: str) -> bool:
        if role_name.startswith("AWSServiceRoleFor"):
            return True
        if "/aws-service-role/" in role_arn:
            return True
        return role_path.startswith("/aws-service-role/")

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
