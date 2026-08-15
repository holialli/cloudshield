"""IAM posture scanner for CloudShield."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from core.awsutil import BOTO_CONFIG, paginate
from core.models import (
    GLOBAL_REGION,
    STATUS_EXCEPTION,
    STATUS_FAIL,
    STATUS_PASS,
    CheckResult,
    Finding,
    error_check,
)
from scanners.policy_analysis import (
    PolicyIssue,
    analyse_policy_document,
    highest_severity,
    summarise,
)

# Re-exported for backwards compatibility: these models used to live here.
__all__ = ["CheckResult", "Finding", "IAMScanner"]

KEY_MAX_AGE_DAYS = 90

#: API shape differences between the three IAM principal types.
_PRINCIPAL_SPECS: Dict[str, Dict[str, str]] = {
    "role": {
        "list_op": "list_roles",
        "list_key": "Roles",
        "name_field": "RoleName",
        "attached_op": "list_attached_role_policies",
        "inline_op": "list_role_policies",
        "get_inline_op": "get_role_policy",
        "name_param": "RoleName",
        "check_id": "IAM-ROLE-WILDCARD",
        "check_name": "IAM role access avoids wildcard action/resource",
    },
    "user": {
        "list_op": "list_users",
        "list_key": "Users",
        "name_field": "UserName",
        "attached_op": "list_attached_user_policies",
        "inline_op": "list_user_policies",
        "get_inline_op": "get_user_policy",
        "name_param": "UserName",
        "check_id": "IAM-USER-WILDCARD",
        "check_name": "IAM user access avoids wildcard action/resource",
    },
    "group": {
        "list_op": "list_groups",
        "list_key": "Groups",
        "name_field": "GroupName",
        "attached_op": "list_attached_group_policies",
        "inline_op": "list_group_policies",
        "get_inline_op": "get_group_policy",
        "name_param": "GroupName",
        "check_id": "IAM-GROUP-WILDCARD",
        "check_name": "IAM group access avoids wildcard action/resource",
    },
}


class IAMScanner:
    """Scan IAM for CIS AWS Foundations issues.

    IAM is a global service, so this scanner runs once per account regardless of
    how many regions are being scanned.
    """

    service = "iam"
    region = GLOBAL_REGION

    def __init__(self, session: boto3.Session) -> None:
        self.iam = session.client("iam", config=BOTO_CONFIG)
        self._managed_policy_cache: Dict[str, List[PolicyIssue]] = {}

    def scan(self) -> List[Finding]:
        findings, _ = self.scan_detailed()
        return findings

    def scan_detailed(self) -> Tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        for scan_step in (
            self._scan_root_mfa,
            self._scan_access_key_age,
            self._scan_customer_managed_policies,
        ):
            step_findings, step_checks = scan_step()
            findings.extend(step_findings)
            checks.extend(step_checks)

        for principal_kind in _PRINCIPAL_SPECS:
            step_findings, step_checks = self._scan_principals(principal_kind)
            findings.extend(step_findings)
            checks.extend(step_checks)

        return findings, checks

    # ------------------------------------------------------------------
    # Root account
    # ------------------------------------------------------------------

    def _scan_root_mfa(self) -> Tuple[List[Finding], List[CheckResult]]:
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
        except (BotoCoreError, ClientError) as exc:
            return [], [
                error_check(
                    service="iam",
                    resource_id="root-account",
                    resource_type="account",
                    check_id="IAM-ROOT-MFA",
                    check_name="Root account MFA enabled",
                    message="Unable to evaluate root MFA status.",
                    error=exc,
                    cis_control="CIS 1.5",
                )
            ]

        enabled = summary.get("AccountMFAEnabled", 0) == 1
        check = CheckResult(
            service="iam",
            resource_id="root-account",
            resource_type="account",
            check_id="IAM-ROOT-MFA",
            check_name="Root account MFA enabled",
            status=STATUS_PASS if enabled else STATUS_FAIL,
            severity="High",
            cis_control="CIS 1.5",
            message=(
                "Root account MFA is enabled."
                if enabled
                else "Root account MFA is disabled."
            ),
            details={"account_mfa_enabled": enabled},
        )
        if enabled:
            return [], [check]

        finding = Finding(
            service="iam",
            resource_id="root-account",
            title="Root account MFA is disabled",
            description="The AWS root account does not have MFA enabled.",
            severity="High",
            cis_control="CIS 1.5",
            remediation="Enable MFA on the root account immediately.",
            details={"account_mfa_enabled": False},
            check_id="IAM-ROOT-MFA",
        )
        return [finding], [check]

    # ------------------------------------------------------------------
    # Access keys
    # ------------------------------------------------------------------

    def _scan_access_key_age(self) -> Tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        try:
            users = list(paginate(self.iam, "list_users", "Users"))
        except (BotoCoreError, ClientError) as exc:
            return [], [
                error_check(
                    service="iam",
                    resource_id="iam-users",
                    resource_type="collection",
                    check_id="IAM-USER-KEY-AGE",
                    check_name="IAM user access keys rotated within 90 days",
                    message="Unable to list IAM users.",
                    error=exc,
                    cis_control="CIS 1.14",
                )
            ]

        now = datetime.now(timezone.utc)
        for user in users:
            user_name = user["UserName"]
            try:
                access_keys = list(
                    paginate(
                        self.iam,
                        "list_access_keys",
                        "AccessKeyMetadata",
                        UserName=user_name,
                    )
                )
            except (BotoCoreError, ClientError) as exc:
                checks.append(
                    error_check(
                        service="iam",
                        resource_id=user_name,
                        resource_type="user",
                        check_id="IAM-USER-KEY-AGE",
                        check_name="IAM user access keys rotated within 90 days",
                        message="Unable to evaluate IAM access key age.",
                        error=exc,
                        severity="Low",
                        cis_control="CIS 1.14",
                        details={"user": user_name},
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
                        status=STATUS_PASS,
                        severity="Medium",
                        cis_control="CIS 1.14",
                        message="User has no IAM access keys.",
                        details={"user": user_name},
                    )
                )
                continue

            for access_key in access_keys:
                key_id = access_key["AccessKeyId"]
                key_status = access_key.get("Status", "Unknown")
                age_days = (now - access_key["CreateDate"]).days
                resource_id = f"{user_name}:{key_id}"
                details = {
                    "user": user_name,
                    "access_key_id": key_id,
                    "age_days": age_days,
                    "key_status": key_status,
                }

                if age_days <= KEY_MAX_AGE_DAYS:
                    checks.append(
                        CheckResult(
                            service="iam",
                            resource_id=resource_id,
                            resource_type="access-key",
                            check_id="IAM-USER-KEY-AGE",
                            check_name="IAM user access keys rotated within 90 days",
                            status=STATUS_PASS,
                            severity="Medium",
                            cis_control="CIS 1.14",
                            message=f"Access key age is within {KEY_MAX_AGE_DAYS} days.",
                            details=details,
                        )
                    )
                    continue

                # An inactive key cannot be used to authenticate, so it is a
                # hygiene problem rather than an exposure.
                severity = "Medium" if key_status == "Active" else "Low"
                findings.append(
                    Finding(
                        service="iam",
                        resource_id=resource_id,
                        title="IAM access key older than 90 days",
                        description=(
                            f"{key_status} access key for user {user_name} is {age_days} days old."
                        ),
                        severity=severity,
                        cis_control="CIS 1.14",
                        remediation="Rotate the access key and remove unused keys.",
                        details=details,
                        check_id="IAM-USER-KEY-AGE",
                    )
                )
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=resource_id,
                        resource_type="access-key",
                        check_id="IAM-USER-KEY-AGE",
                        check_name="IAM user access keys rotated within 90 days",
                        status=STATUS_FAIL,
                        severity=severity,
                        cis_control="CIS 1.14",
                        message=f"{key_status} access key is {age_days} days old.",
                        details=details,
                    )
                )

        return findings, checks

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def _scan_customer_managed_policies(self) -> Tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        try:
            policies = list(
                paginate(
                    self.iam,
                    "list_policies",
                    "Policies",
                    Scope="Local",
                    OnlyAttached=False,
                )
            )
        except (BotoCoreError, ClientError) as exc:
            return [], [
                error_check(
                    service="iam",
                    resource_id="iam-policies",
                    resource_type="collection",
                    check_id="IAM-POLICY-WILDCARD",
                    check_name="IAM policy avoids wildcard action/resource",
                    message="Unable to list IAM policies.",
                    error=exc,
                    cis_control="CIS 1.16",
                )
            ]

        for policy in policies:
            policy_arn = policy["Arn"]
            policy_name = policy["PolicyName"]
            attachment_count = int(policy.get("AttachmentCount", 0) or 0)

            document = self._policy_document(policy_arn, policy.get("DefaultVersionId"))
            if document is None:
                checks.append(
                    error_check(
                        service="iam",
                        resource_id=policy_arn,
                        resource_type="policy",
                        check_id="IAM-POLICY-WILDCARD",
                        check_name="IAM policy avoids wildcard action/resource",
                        message="Unable to inspect IAM policy document.",
                        error="policy document could not be retrieved",
                        severity="Low",
                        cis_control="CIS 1.16",
                        details={"policy_name": policy_name},
                    )
                )
                continue

            issues = analyse_policy_document(document)
            details = {
                "policy_name": policy_name,
                "policy_arn": policy_arn,
                "attachment_count": attachment_count,
                "issues": [issue.to_dict() for issue in issues],
            }

            if not issues:
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=policy_arn,
                        resource_type="policy",
                        check_id="IAM-POLICY-WILDCARD",
                        check_name="IAM policy avoids wildcard action/resource",
                        status=STATUS_PASS,
                        severity="High",
                        cis_control="CIS 1.16",
                        message=f"Policy {policy_name} is scoped without wildcard action/resource.",
                        details=details,
                    )
                )
                continue

            severity = highest_severity(issues)
            # An unattached policy grants nothing today; it is latent risk only.
            if attachment_count == 0 and severity == "High":
                severity = "Medium"
            summary = summarise(issues)

            findings.append(
                Finding(
                    service="iam",
                    resource_id=policy_arn,
                    title="IAM policy contains wildcard permissions",
                    description=f"Policy {policy_name}: {summary}.",
                    severity=severity,
                    cis_control="CIS 1.16",
                    remediation="Replace wildcard permissions with scoped IAM actions and resources.",
                    details=details,
                    check_id="IAM-POLICY-WILDCARD",
                )
            )
            checks.append(
                CheckResult(
                    service="iam",
                    resource_id=policy_arn,
                    resource_type="policy",
                    check_id="IAM-POLICY-WILDCARD",
                    check_name="IAM policy avoids wildcard action/resource",
                    status=STATUS_FAIL,
                    severity=severity,
                    cis_control="CIS 1.16",
                    message=f"Policy {policy_name}: {summary}."
                    + ("" if attachment_count else " (not currently attached)"),
                    details=details,
                )
            )

        return findings, checks

    def _policy_document(
        self, policy_arn: str, default_version_id: Optional[str] = None
    ) -> Optional[Any]:
        try:
            if not default_version_id:
                default_version_id = self.iam.get_policy(PolicyArn=policy_arn)["Policy"][
                    "DefaultVersionId"
                ]
            return self.iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=default_version_id
            )["PolicyVersion"]["Document"]
        except (BotoCoreError, ClientError, KeyError):
            return None

    def _managed_policy_issues(self, policy_arn: str) -> List[PolicyIssue]:
        """Analyse a managed policy once and reuse it across principals."""

        if policy_arn not in self._managed_policy_cache:
            document = self._policy_document(policy_arn)
            self._managed_policy_cache[policy_arn] = (
                analyse_policy_document(document) if document is not None else []
            )
        return self._managed_policy_cache[policy_arn]

    # ------------------------------------------------------------------
    # Principals (roles, users, groups)
    # ------------------------------------------------------------------

    def _scan_principals(self, kind: str) -> Tuple[List[Finding], List[CheckResult]]:
        spec = _PRINCIPAL_SPECS[kind]
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        try:
            principals = list(paginate(self.iam, spec["list_op"], spec["list_key"]))
        except (BotoCoreError, ClientError) as exc:
            return [], [
                error_check(
                    service="iam",
                    resource_id=f"iam-{kind}s",
                    resource_type="collection",
                    check_id=spec["check_id"],
                    check_name=spec["check_name"],
                    message=f"Unable to list IAM {kind}s.",
                    error=exc,
                    cis_control="CIS 1.16",
                )
            ]

        for principal in principals:
            name = principal[spec["name_field"]]
            arn = principal.get("Arn", name)
            issues: List[PolicyIssue] = []
            sources: List[str] = []
            inspection_failed = False

            try:
                attached = list(
                    paginate(
                        self.iam,
                        spec["attached_op"],
                        "AttachedPolicies",
                        **{spec["name_param"]: name},
                    )
                )
            except (BotoCoreError, ClientError) as exc:
                checks.append(
                    error_check(
                        service="iam",
                        resource_id=arn,
                        resource_type=kind,
                        check_id=spec["check_id"],
                        check_name=spec["check_name"],
                        message=f"Unable to inspect attached {kind} policies.",
                        error=exc,
                        severity="Low",
                        cis_control="CIS 1.16",
                        details={"name": name},
                    )
                )
                continue

            for attached_policy in attached:
                policy_issues = self._managed_policy_issues(attached_policy["PolicyArn"])
                if policy_issues:
                    issues.extend(policy_issues)
                    sources.append(attached_policy["PolicyName"])

            try:
                inline_names = list(
                    paginate(
                        self.iam,
                        spec["inline_op"],
                        "PolicyNames",
                        **{spec["name_param"]: name},
                    )
                )
            except (BotoCoreError, ClientError):
                inline_names = []
                inspection_failed = True

            for inline_name in inline_names:
                try:
                    document = getattr(self.iam, spec["get_inline_op"])(
                        **{spec["name_param"]: name, "PolicyName": inline_name}
                    )["PolicyDocument"]
                except (BotoCoreError, ClientError, KeyError):
                    inspection_failed = True
                    continue

                inline_issues = analyse_policy_document(document)
                if inline_issues:
                    issues.extend(inline_issues)
                    sources.append(f"inline:{inline_name}")

            details: Dict[str, Any] = {
                "name": name,
                "arn": arn,
                "wildcard_policies": sources,
                "issues": [issue.to_dict() for issue in issues],
            }
            if inspection_failed:
                details["partial_inspection"] = True

            if issues and kind == "role" and self._is_service_linked_role(principal):
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=arn,
                        resource_type="role",
                        check_id=spec["check_id"],
                        check_name=spec["check_name"],
                        status=STATUS_EXCEPTION,
                        severity="Informational",
                        cis_control="CIS 1.16",
                        message="AWS-managed service-linked role uses wildcard access (exception).",
                        details={**details, "exception_type": "AWS-Managed Service-Linked Role"},
                    )
                )
                continue

            if not issues:
                checks.append(
                    CheckResult(
                        service="iam",
                        resource_id=arn,
                        resource_type=kind,
                        check_id=spec["check_id"],
                        check_name=spec["check_name"],
                        status=STATUS_PASS,
                        severity="High",
                        cis_control="CIS 1.16",
                        message=f"{kind.capitalize()} policies are scoped without wildcard action/resource.",
                        details=details,
                    )
                )
                continue

            severity = highest_severity(issues)
            summary = summarise(issues)
            findings.append(
                Finding(
                    service="iam",
                    resource_id=arn,
                    title=f"IAM {kind} has wildcard access",
                    description=(
                        f"{kind.capitalize()} {name} via {', '.join(sources) or 'policy'}: {summary}."
                    ),
                    severity=severity,
                    cis_control="CIS 1.16",
                    remediation="Replace wildcard permissions with least-privilege scoped actions and resources.",
                    details=details,
                    check_id=spec["check_id"],
                )
            )
            checks.append(
                CheckResult(
                    service="iam",
                    resource_id=arn,
                    resource_type=kind,
                    check_id=spec["check_id"],
                    check_name=spec["check_name"],
                    status=STATUS_FAIL,
                    severity=severity,
                    cis_control="CIS 1.16",
                    message=f"{summary} (via {', '.join(sources) or 'policy'}).",
                    details=details,
                )
            )

        return findings, checks

    @staticmethod
    def _is_service_linked_role(role: Dict[str, Any]) -> bool:
        name = str(role.get("RoleName", ""))
        arn = str(role.get("Arn", ""))
        path = str(role.get("Path", ""))
        return (
            name.startswith("AWSServiceRoleFor")
            or "/aws-service-role/" in arn
            or path.startswith("/aws-service-role/")
        )

    @staticmethod
    def _contains_wildcard_permissions(document: Dict[str, Any]) -> bool:
        """Deprecated: retained for callers outside this module."""

        return bool(analyse_policy_document(document))
