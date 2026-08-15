"""The remediation registry: one entry per check that CloudShield can fix.

This is the single source of truth for "what do we do about check X". The PDF
report and the standalone ``remediate.py`` runner both read from it, so the
documented advice and the executed action can no longer drift apart.

Every action is a boto3 call. Nothing is shelled out, so no resource identifier
is ever interpolated into a command string that a shell will parse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from core.awsutil import BOTO_CONFIG
from core.models import CheckResult

ApplyFn = Callable[[boto3.Session, CheckResult], str]

STATUS_APPLIED = "applied"
STATUS_PLANNED = "planned"
STATUS_SKIPPED = "skipped"
STATUS_FAILED = "failed"
STATUS_UNSUPPORTED = "unsupported"

FALLBACK_DOC = (
    "https://docs.aws.amazon.com/securityhub/latest/userguide/"
    "securityhub-standards-fsbp-controls.html"
)


@dataclass(frozen=True)
class Remediation:
    """A remediation for one check id."""

    check_id: str
    description: str
    doc_url: str
    #: True when applying this can break a working workload (revoking access,
    #: disabling a credential). Destructive actions are called out in the plan
    #: and, like every action, require explicit --allow to run.
    destructive: bool = False
    apply: Optional[ApplyFn] = None
    #: Renders the equivalent AWS CLI command with this check's real resource
    #: identifiers substituted in. Display only -- never executed.
    command: Callable[[CheckResult], str] = field(
        default=lambda check: "Review the resource and apply least-privilege hardening."
    )

    @property
    def automated(self) -> bool:
        return self.apply is not None


@dataclass
class RemediationResult:
    check_id: str
    resource_id: str
    region: str
    status: str
    message: str
    command: str = ""
    destructive: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "check_id": self.check_id,
            "resource_id": self.resource_id,
            "region": self.region,
            "status": self.status,
            "message": self.message,
            "command": self.command,
            "destructive": self.destructive,
        }


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

_PAB_CONFIG = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

_PAB_CLI = (
    "BlockPublicAcls=true,IgnorePublicAcls=true,"
    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
)


def _bucket_of(check: CheckResult) -> str:
    bucket = check.details.get("bucket") or check.resource_id
    if not bucket or str(bucket).startswith("account:"):
        raise ValueError(f"{check.check_id} on {check.resource_id} has no bucket to act on")
    return str(bucket)


def _account_of(check: CheckResult) -> str:
    account_id = check.details.get("account_id") or check.resource_id.replace("account:", "")
    if not account_id:
        raise ValueError(f"{check.check_id} has no account id to act on")
    return str(account_id)


def _client(session: boto3.Session, service: str, check: CheckResult):
    region = check.region if check.region and check.region != "global" else None
    return session.client(service, region_name=region, config=BOTO_CONFIG)


def _region_flag(check: CheckResult) -> str:
    """Render ``--region x`` only when we actually know the region."""

    if check.region and check.region != "global":
        return f" --region {check.region}"
    return ""


def _permissions_from_rules(rules: Sequence[dict]) -> List[dict]:
    permissions: List[dict] = []
    for rule in rules:
        permission: Dict[str, object] = {"IpProtocol": str(rule.get("protocol", "-1"))}
        if rule.get("from_port") is not None:
            permission["FromPort"] = rule["from_port"]
        if rule.get("to_port") is not None:
            permission["ToPort"] = rule["to_port"]
        sources = rule.get("sources", []) or []
        ipv4 = [{"CidrIp": s} for s in sources if ":" not in s]
        ipv6 = [{"CidrIpv6": s} for s in sources if ":" in s]
        if ipv4:
            permission["IpRanges"] = ipv4
        if ipv6:
            permission["Ipv6Ranges"] = ipv6
        if ipv4 or ipv6:
            permissions.append(permission)
    return permissions


# ----------------------------------------------------------------------
# Apply functions
# ----------------------------------------------------------------------


def _fix_bucket_pab(session: boto3.Session, check: CheckResult) -> str:
    bucket = _bucket_of(check)
    _client(session, "s3", check).put_public_access_block(
        Bucket=bucket, PublicAccessBlockConfiguration=_PAB_CONFIG
    )
    return f"Enabled all Public Access Block controls on bucket {bucket}."


def _fix_account_pab(session: boto3.Session, check: CheckResult) -> str:
    account_id = _account_of(check)
    session.client("s3control", config=BOTO_CONFIG).put_public_access_block(
        AccountId=account_id, PublicAccessBlockConfiguration=_PAB_CONFIG
    )
    return f"Enabled all account-level Public Access Block controls for {account_id}."


def _fix_ebs_default_encryption(session: boto3.Session, check: CheckResult) -> str:
    _client(session, "ec2", check).enable_ebs_encryption_by_default()
    return f"Enabled EBS encryption by default in {check.region}."


def _fix_imdsv2(session: boto3.Session, check: CheckResult) -> str:
    instance_id = check.details.get("instance_id") or check.resource_id
    _client(session, "ec2", check).modify_instance_metadata_options(
        InstanceId=instance_id, HttpTokens="required", HttpEndpoint="enabled"
    )
    return f"Required IMDSv2 on instance {instance_id}."


def _fix_access_key(session: boto3.Session, check: CheckResult) -> str:
    user = check.details.get("user")
    key_id = check.details.get("access_key_id")
    if not user or not key_id:
        raise ValueError("access key remediation needs both 'user' and 'access_key_id'")
    session.client("iam", config=BOTO_CONFIG).update_access_key(
        UserName=user, AccessKeyId=key_id, Status="Inactive"
    )
    return f"Deactivated access key {key_id} for user {user}."


def _fix_risky_ingress(session: boto3.Session, check: CheckResult) -> str:
    group_id = check.details.get("group_id") or check.resource_id
    permissions = _permissions_from_rules(check.details.get("risky_rules", []))
    if not permissions:
        raise ValueError("no revocable ingress rules recorded on this check")
    _client(session, "ec2", check).revoke_security_group_ingress(
        GroupId=group_id, IpPermissions=permissions
    )
    return f"Revoked {len(permissions)} public ingress rule(s) from {group_id}."


def _fix_default_sg(session: boto3.Session, check: CheckResult) -> str:
    group_id = check.details.get("group_id") or check.resource_id
    ec2 = _client(session, "ec2", check)
    groups = ec2.describe_security_groups(GroupIds=[group_id]).get("SecurityGroups", [])
    if not groups:
        raise ValueError(f"security group {group_id} not found")

    group = groups[0]
    revoked = 0
    if group.get("IpPermissions"):
        ec2.revoke_security_group_ingress(
            GroupId=group_id, IpPermissions=group["IpPermissions"]
        )
        revoked += len(group["IpPermissions"])
    if group.get("IpPermissionsEgress"):
        ec2.revoke_security_group_egress(
            GroupId=group_id, IpPermissions=group["IpPermissionsEgress"]
        )
        revoked += len(group["IpPermissionsEgress"])
    return f"Removed {revoked} rule(s) from default security group {group_id}."


# ----------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------

REMEDIATIONS: Dict[str, Remediation] = {
    "S3-PUBLIC-ACCESS-BLOCK": Remediation(
        check_id="S3-PUBLIC-ACCESS-BLOCK",
        description="Enable all bucket-level S3 Public Access Block controls.",
        doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        destructive=True,  # breaks buckets that intentionally serve public content
        apply=_fix_bucket_pab,
        command=lambda c: (
            f"aws s3api put-public-access-block --bucket {c.details.get('bucket', c.resource_id)} "
            f"--public-access-block-configuration {_PAB_CLI}"
        ),
    ),
    "S3-ACCOUNT-PUBLIC-ACCESS-BLOCK": Remediation(
        check_id="S3-ACCOUNT-PUBLIC-ACCESS-BLOCK",
        description="Enable all account-level S3 Public Access Block controls.",
        doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        destructive=True,
        apply=_fix_account_pab,
        command=lambda c: (
            "aws s3control put-public-access-block --account-id "
            f"{c.details.get('account_id', c.resource_id.replace('account:', ''))} "
            f"--public-access-block-configuration {_PAB_CLI}"
        ),
    ),
    "EC2-EBS-ENCRYPTION-BY-DEFAULT": Remediation(
        check_id="EC2-EBS-ENCRYPTION-BY-DEFAULT",
        description="Enable account-level EBS encryption by default for this region.",
        doc_url="https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html",
        apply=_fix_ebs_default_encryption,
        command=lambda c: f"aws ec2 enable-ebs-encryption-by-default{_region_flag(c)}",
    ),
    "EC2-IMDSV2-REQUIRED": Remediation(
        check_id="EC2-IMDSV2-REQUIRED",
        description="Require IMDSv2 on the affected instance.",
        doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        apply=_fix_imdsv2,
        command=lambda c: (
            "aws ec2 modify-instance-metadata-options --instance-id "
            f"{c.details.get('instance_id', c.resource_id)} --http-tokens required "
            f"--http-endpoint enabled{_region_flag(c)}"
        ),
    ),
    "EC2-SG-RISKY-PUBLIC-INGRESS": Remediation(
        check_id="EC2-SG-RISKY-PUBLIC-INGRESS",
        description=(
            "Revoke the public ingress rules exposing SSH/RDP. This removes the whole "
            "matching rule, including any other ports in the same range."
        ),
        doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html",
        destructive=True,
        apply=_fix_risky_ingress,
        command=lambda c: (
            "aws ec2 revoke-security-group-ingress --group-id "
            f"{c.details.get('group_id', c.resource_id)}{_region_flag(c)} "
            "--ip-permissions <the rules listed in this finding's details>"
        ),
    ),
    "EC2-DEFAULT-SG-HARDENED": Remediation(
        check_id="EC2-DEFAULT-SG-HARDENED",
        description="Remove every ingress and egress rule from the default security group.",
        doc_url="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",
        destructive=True,
        apply=_fix_default_sg,
        command=lambda c: (
            "aws ec2 revoke-security-group-ingress/egress --group-id "
            f"{c.details.get('group_id', c.resource_id)}{_region_flag(c)} "
            "--ip-permissions <all existing rules>"
        ),
    ),
    "IAM-USER-KEY-AGE": Remediation(
        check_id="IAM-USER-KEY-AGE",
        description="Deactivate the stale access key. Rotate before deleting it.",
        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        destructive=True,
        apply=_fix_access_key,
        command=lambda c: (
            f"aws iam update-access-key --user-name {c.details.get('user', '<user>')} "
            f"--access-key-id {c.details.get('access_key_id', '<key>')} --status Inactive"
        ),
    ),
    # Documented but not automated: these need a human decision about what the
    # correct scoped replacement is.
    "IAM-ROOT-MFA": Remediation(
        check_id="IAM-ROOT-MFA",
        description="Enable MFA on the root account (console only, root credentials required).",
        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_mfa.html",
    ),
    "IAM-POLICY-WILDCARD": Remediation(
        check_id="IAM-POLICY-WILDCARD",
        description="Replace wildcard Action/Resource entries with scoped values.",
        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    ),
    "IAM-ROLE-WILDCARD": Remediation(
        check_id="IAM-ROLE-WILDCARD",
        description="Refactor the role's policies to least privilege.",
        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    ),
    "IAM-USER-WILDCARD": Remediation(
        check_id="IAM-USER-WILDCARD",
        description="Move the user's permissions into a scoped group policy.",
        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    ),
    "IAM-GROUP-WILDCARD": Remediation(
        check_id="IAM-GROUP-WILDCARD",
        description="Refactor the group's policies to least privilege.",
        doc_url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    ),
    "S3-BUCKET-ACL-PUBLIC": Remediation(
        check_id="S3-BUCKET-ACL-PUBLIC",
        description="Remove the public ACL grants, then enable Block Public Access.",
        doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html",
    ),
    "S3-BUCKET-POLICY-PUBLIC": Remediation(
        check_id="S3-BUCKET-POLICY-PUBLIC",
        description="Remove the public principal from the bucket policy.",
        doc_url="https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html",
    ),
    "EC2-EBS-VOLUME-ENCRYPTED": Remediation(
        check_id="EC2-EBS-VOLUME-ENCRYPTED",
        description="Snapshot the volume, copy the snapshot with encryption, replace the volume.",
        doc_url="https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html",
    ),
    "EC2-NO-PUBLIC-IP": Remediation(
        check_id="EC2-NO-PUBLIC-IP",
        description="Move the instance to a private subnet behind a NAT gateway or load balancer.",
        doc_url="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
    ),
}


def lookup(check_id: str) -> Optional[Remediation]:
    return REMEDIATIONS.get(check_id)


def describe(check: CheckResult) -> tuple[str, str, str]:
    """Return ``(description, command, doc_url)`` for a check, for reporting."""

    remediation = REMEDIATIONS.get(check.check_id)
    if remediation is None:
        return (
            "Review the resource and apply least-privilege hardening for this check.",
            "",
            FALLBACK_DOC,
        )
    return remediation.description, remediation.command(check), remediation.doc_url


def actionable_checks(checks: Sequence[CheckResult]) -> List[CheckResult]:
    """Failed, unsuppressed checks that have an automated remediation."""

    actionable: List[CheckResult] = []
    for check in checks:
        if check.status != "FAIL" or check.suppressed:
            continue
        remediation = REMEDIATIONS.get(check.check_id)
        if remediation is not None and remediation.automated:
            actionable.append(check)
    return actionable


def run(
    session: boto3.Session,
    checks: Sequence[CheckResult],
    *,
    allow: Sequence[str] = (),
    apply_changes: bool = False,
) -> List[RemediationResult]:
    """Plan (and optionally apply) remediations for the given checks.

    Nothing is applied unless ``apply_changes`` is True *and* the check id is in
    ``allow`` (or ``allow`` contains ``"all"``). The default is a plan.
    """

    allowed = {item.upper() for item in allow}
    allow_all = "ALL" in allowed
    results: List[RemediationResult] = []

    for check in checks:
        if check.status != "FAIL" or check.suppressed:
            continue

        remediation = REMEDIATIONS.get(check.check_id)
        if remediation is None or not remediation.automated:
            continue

        command = remediation.command(check)
        base = {
            "check_id": check.check_id,
            "resource_id": check.resource_id,
            "region": check.region,
            "command": command,
            "destructive": remediation.destructive,
        }

        if not (allow_all or check.check_id.upper() in allowed):
            results.append(
                RemediationResult(
                    status=STATUS_SKIPPED,
                    message=f"Not allowed. Re-run with --allow {check.check_id} to apply.",
                    **base,
                )
            )
            continue

        if not apply_changes:
            results.append(
                RemediationResult(
                    status=STATUS_PLANNED,
                    message=remediation.description,
                    **base,
                )
            )
            continue

        try:
            message = remediation.apply(session, check)  # type: ignore[misc]
        except (BotoCoreError, ClientError, ValueError) as exc:
            # A remediation failure must never abort the run: the remaining
            # fixes still need to be attempted and the report still needs writing.
            results.append(
                RemediationResult(status=STATUS_FAILED, message=str(exc), **base)
            )
            continue

        results.append(RemediationResult(status=STATUS_APPLIED, message=message, **base))

    return results
