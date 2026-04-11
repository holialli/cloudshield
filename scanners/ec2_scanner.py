"""EC2 security group scanner for CloudShield."""

from __future__ import annotations

from typing import Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanners.iam_scanner import CheckResult, Finding


class EC2Scanner:
    """Scan EC2 and related controls for risky exposure and weak hardening."""

    def __init__(self, session: boto3.Session) -> None:
        self.ec2 = session.client("ec2")

    def scan(self) -> List[Finding]:
        findings, _ = self.scan_detailed()
        return findings

    def scan_detailed(self) -> tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        ebs_default_enabled = self._scan_ebs_encryption_default(findings, checks)

        try:
            security_groups = self.ec2.describe_security_groups().get(
                "SecurityGroups", []
            )
        except (BotoCoreError, ClientError) as exc:
            finding = Finding(
                    service="ec2",
                    resource_id="security-groups",
                    title="Unable to list security groups",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 5.1",
                    remediation="Review EC2 permissions and API access.",
                    details={"error": str(exc)},
                )
            check = CheckResult(
                service="ec2",
                resource_id="security-groups",
                resource_type="collection",
                check_id="EC2-SG-LIST",
                check_name="EC2 security groups can be listed",
                status="ERROR",
                severity="Medium",
                cis_control="CIS 5.1",
                message="Unable to list security groups.",
                details={"error": str(exc)},
            )
            return [finding], [check]

        for security_group in security_groups:
            group_id = security_group.get("GroupId", "unknown")
            group_name = security_group.get("GroupName", group_id)
            insecure_rules: List[dict] = []
            open_all_rules: List[dict] = []
            for permission in security_group.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                if not self._is_risky_port(from_port, to_port):
                    if self._permission_opens_all_traffic(permission):
                        open_all_rules.append(
                            {
                                "protocol": permission.get("IpProtocol", "unknown"),
                                "from_port": from_port,
                                "to_port": to_port,
                            }
                        )
                    continue

                if self._open_to_world(permission):
                    insecure_rules.append({"from_port": from_port, "to_port": to_port})
                    findings.append(
                        Finding(
                            service="ec2",
                            resource_id=group_id,
                            title="Security group allows risky public ingress",
                            description=(
                                f"Security group {group_name} exposes port {from_port} to public internet."
                            ),
                            severity="High",
                            cis_control=self._cis_control_for_port(from_port),
                            remediation=(
                                "Restrict inbound access to trusted IP ranges or use a VPN/bastion host."
                            ),
                            details={
                                "group_id": group_id,
                                "group_name": group_name,
                                "from_port": from_port,
                                "to_port": to_port,
                            },
                        )
                    )

                if self._permission_opens_all_traffic(permission):
                    open_all_rules.append(
                        {
                            "protocol": permission.get("IpProtocol", "unknown"),
                            "from_port": from_port,
                            "to_port": to_port,
                        }
                    )

            if insecure_rules:
                checks.append(
                    CheckResult(
                        service="ec2",
                        resource_id=group_id,
                        resource_type="security-group",
                        check_id="EC2-SG-RISKY-PUBLIC-INGRESS",
                        check_name="Security group blocks public SSH/RDP ingress",
                        status="FAIL",
                        severity="High",
                        cis_control="CIS 5.1",
                        message="Security group exposes SSH/RDP to 0.0.0.0/0.",
                        details={
                            "group_id": group_id,
                            "group_name": group_name,
                            "insecure_rules": insecure_rules,
                        },
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        service="ec2",
                        resource_id=group_id,
                        resource_type="security-group",
                        check_id="EC2-SG-RISKY-PUBLIC-INGRESS",
                        check_name="Security group blocks public SSH/RDP ingress",
                        status="PASS",
                        severity="High",
                        cis_control="CIS 5.1",
                        message="Security group has no public SSH/RDP exposure.",
                        details={"group_id": group_id, "group_name": group_name},
                    )
                )

            if open_all_rules:
                findings.append(
                    Finding(
                        service="ec2",
                        resource_id=group_id,
                        title="Security group allows all traffic from the internet",
                        description=(
                            f"Security group {group_name} has protocol -1 open to world."
                        ),
                        severity="High",
                        cis_control="CIS 5.3",
                        remediation="Remove broad public ingress and scope protocol/ports to trusted networks.",
                        details={
                            "group_id": group_id,
                            "group_name": group_name,
                            "open_all_rules": open_all_rules,
                        },
                    )
                )
                checks.append(
                    CheckResult(
                        service="ec2",
                        resource_id=group_id,
                        resource_type="security-group",
                        check_id="EC2-SG-NO-ALL-TRAFFIC",
                        check_name="Security group blocks public all-traffic ingress",
                        status="FAIL",
                        severity="High",
                        cis_control="CIS 5.3",
                        message="Security group allows all protocols from public internet.",
                        details={
                            "group_id": group_id,
                            "group_name": group_name,
                            "open_all_rules": open_all_rules,
                        },
                    )
                )
            else:
                checks.append(
                    CheckResult(
                        service="ec2",
                        resource_id=group_id,
                        resource_type="security-group",
                        check_id="EC2-SG-NO-ALL-TRAFFIC",
                        check_name="Security group blocks public all-traffic ingress",
                        status="PASS",
                        severity="High",
                        cis_control="CIS 5.3",
                        message="Security group does not allow all-protocol public ingress.",
                        details={"group_id": group_id, "group_name": group_name},
                    )
                )

            if group_name == "default":
                default_open_ingress = any(
                    self._open_to_world(permission)
                    for permission in security_group.get("IpPermissions", [])
                )
                default_open_egress = any(
                    self._open_to_world(permission)
                    for permission in security_group.get("IpPermissionsEgress", [])
                )
                if default_open_ingress or default_open_egress:
                    findings.append(
                        Finding(
                            service="ec2",
                            resource_id=group_id,
                            title="Default security group allows public traffic",
                            description=(
                                "Default security group has public ingress or egress rules."
                            ),
                            severity="Medium",
                            cis_control="CIS 5.4",
                            remediation="Harden default security group to deny public ingress and egress.",
                            details={
                                "group_id": group_id,
                                "group_name": group_name,
                                "public_ingress": default_open_ingress,
                                "public_egress": default_open_egress,
                            },
                        )
                    )
                    checks.append(
                        CheckResult(
                            service="ec2",
                            resource_id=group_id,
                            resource_type="security-group",
                            check_id="EC2-DEFAULT-SG-HARDENED",
                            check_name="Default security group is hardened",
                            status="FAIL",
                            severity="Medium",
                            cis_control="CIS 5.4",
                            message="Default security group has public ingress or egress.",
                            details={
                                "group_id": group_id,
                                "public_ingress": default_open_ingress,
                                "public_egress": default_open_egress,
                            },
                        )
                    )
                else:
                    checks.append(
                        CheckResult(
                            service="ec2",
                            resource_id=group_id,
                            resource_type="security-group",
                            check_id="EC2-DEFAULT-SG-HARDENED",
                            check_name="Default security group is hardened",
                            status="PASS",
                            severity="Medium",
                            cis_control="CIS 5.4",
                            message="Default security group does not allow public ingress/egress.",
                            details={"group_id": group_id, "group_name": group_name},
                        )
                    )

        self._scan_instances(findings, checks, ebs_default_enabled)

        return findings, checks

    def _scan_ebs_encryption_default(
        self, findings: List[Finding], checks: List[CheckResult]
    ) -> bool:
        try:
            ebs_default_enabled = self.ec2.get_ebs_encryption_by_default().get(
                "EbsEncryptionByDefault", False
            )
        except (BotoCoreError, ClientError) as exc:
            findings.append(
                Finding(
                    service="ec2",
                    resource_id="account-ebs-encryption",
                    title="Unable to evaluate EBS encryption by default",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 2.2.1",
                    remediation="Verify account-level EBS encryption settings manually.",
                    details={"error": str(exc)},
                )
            )
            checks.append(
                CheckResult(
                    service="ec2",
                    resource_id="account-ebs-encryption",
                    resource_type="account",
                    check_id="EC2-EBS-ENCRYPTION-BY-DEFAULT",
                    check_name="EBS encryption by default is enabled",
                    status="ERROR",
                    severity="Medium",
                    cis_control="CIS 2.2.1",
                    message="Unable to evaluate account-level EBS encryption default.",
                    details={"error": str(exc)},
                )
            )
            return False

        if ebs_default_enabled:
            checks.append(
                CheckResult(
                    service="ec2",
                    resource_id="account-ebs-encryption",
                    resource_type="account",
                    check_id="EC2-EBS-ENCRYPTION-BY-DEFAULT",
                    check_name="EBS encryption by default is enabled",
                    status="PASS",
                    severity="Medium",
                    cis_control="CIS 2.2.1",
                    message="Account-level EBS encryption by default is enabled.",
                    details={"ebs_encryption_by_default": True},
                )
            )
            return True

        findings.append(
            Finding(
                service="ec2",
                resource_id="account-ebs-encryption",
                title="EBS encryption by default is disabled",
                description="New EBS volumes may be created unencrypted by default.",
                severity="Medium",
                cis_control="CIS 2.2.1",
                remediation="Enable EBS encryption by default for the AWS region.",
                details={"ebs_encryption_by_default": False},
            )
        )
        checks.append(
            CheckResult(
                service="ec2",
                resource_id="account-ebs-encryption",
                resource_type="account",
                check_id="EC2-EBS-ENCRYPTION-BY-DEFAULT",
                check_name="EBS encryption by default is enabled",
                status="FAIL",
                severity="Medium",
                cis_control="CIS 2.2.1",
                message="Account-level EBS encryption by default is disabled.",
                details={"ebs_encryption_by_default": False},
            )
        )
        return False

    def _scan_instances(
        self,
        findings: List[Finding],
        checks: List[CheckResult],
        ebs_default_enabled: bool,
    ) -> None:
        try:
            paginator = self.ec2.get_paginator("describe_instances")
            pages = paginator.paginate()
        except (BotoCoreError, ClientError) as exc:
            findings.append(
                Finding(
                    service="ec2",
                    resource_id="instances",
                    title="Unable to list EC2 instances",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 4.2",
                    remediation="Review EC2 permissions and API access.",
                    details={"error": str(exc)},
                )
            )
            checks.append(
                CheckResult(
                    service="ec2",
                    resource_id="instances",
                    resource_type="collection",
                    check_id="EC2-INSTANCE-LIST",
                    check_name="EC2 instances can be listed",
                    status="ERROR",
                    severity="Medium",
                    cis_control="CIS 4.2",
                    message="Unable to list EC2 instances.",
                    details={"error": str(exc)},
                )
            )
            return

        volume_to_instance: Dict[str, str] = {}
        for page in pages:
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId", "unknown-instance")

                    metadata_options = instance.get("MetadataOptions", {})
                    imds_tokens = metadata_options.get("HttpTokens", "optional")
                    if imds_tokens == "required":
                        checks.append(
                            CheckResult(
                                service="ec2",
                                resource_id=instance_id,
                                resource_type="instance",
                                check_id="EC2-IMDSV2-REQUIRED",
                                check_name="EC2 instance requires IMDSv2",
                                status="PASS",
                                severity="High",
                                cis_control="CIS 4.2",
                                message="IMDSv2 is required for this instance.",
                                details={"http_tokens": imds_tokens},
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                service="ec2",
                                resource_id=instance_id,
                                title="EC2 instance does not require IMDSv2",
                                description="Instance metadata service v2 enforcement is not enabled.",
                                severity="High",
                                cis_control="CIS 4.2",
                                remediation="Set metadata options HttpTokens to required.",
                                details={"http_tokens": imds_tokens},
                            )
                        )
                        checks.append(
                            CheckResult(
                                service="ec2",
                                resource_id=instance_id,
                                resource_type="instance",
                                check_id="EC2-IMDSV2-REQUIRED",
                                check_name="EC2 instance requires IMDSv2",
                                status="FAIL",
                                severity="High",
                                cis_control="CIS 4.2",
                                message="IMDSv2 is not required for this instance.",
                                details={"http_tokens": imds_tokens},
                            )
                        )

                    public_ip = instance.get("PublicIpAddress")
                    if not public_ip:
                        for network_interface in instance.get("NetworkInterfaces", []):
                            association = network_interface.get("Association", {})
                            if association.get("PublicIp"):
                                public_ip = association.get("PublicIp")
                                break

                    if public_ip:
                        findings.append(
                            Finding(
                                service="ec2",
                                resource_id=instance_id,
                                title="EC2 instance has a public IP address",
                                description="Instance is directly internet-addressable.",
                                severity="Medium",
                                cis_control="CIS 5.1",
                                remediation="Place instance in private subnet or restrict inbound exposure.",
                                details={"public_ip": public_ip},
                            )
                        )
                        checks.append(
                            CheckResult(
                                service="ec2",
                                resource_id=instance_id,
                                resource_type="instance",
                                check_id="EC2-NO-PUBLIC-IP",
                                check_name="EC2 instance avoids public IP exposure",
                                status="FAIL",
                                severity="Medium",
                                cis_control="CIS 5.1",
                                message="Instance has a public IP address.",
                                details={"public_ip": public_ip},
                            )
                        )
                    else:
                        checks.append(
                            CheckResult(
                                service="ec2",
                                resource_id=instance_id,
                                resource_type="instance",
                                check_id="EC2-NO-PUBLIC-IP",
                                check_name="EC2 instance avoids public IP exposure",
                                status="PASS",
                                severity="Medium",
                                cis_control="CIS 5.1",
                                message="Instance has no public IP address.",
                                details={},
                            )
                        )

                    volume_ids = [
                        mapping.get("Ebs", {}).get("VolumeId")
                        for mapping in instance.get("BlockDeviceMappings", [])
                        if mapping.get("Ebs", {}).get("VolumeId")
                    ]
                    for volume_id in volume_ids:
                        volume_to_instance[volume_id] = instance_id

        self._scan_volume_encryption(findings, checks, volume_to_instance, ebs_default_enabled)

    def _scan_volume_encryption(
        self,
        findings: List[Finding],
        checks: List[CheckResult],
        volume_to_instance: Dict[str, str],
        ebs_default_enabled: bool,
    ) -> None:
        if not volume_to_instance:
            return

        volume_ids = list(volume_to_instance.keys())
        for start in range(0, len(volume_ids), 200):
            chunk = volume_ids[start : start + 200]
            try:
                volumes = self.ec2.describe_volumes(VolumeIds=chunk).get("Volumes", [])
            except (BotoCoreError, ClientError) as exc:
                for volume_id in chunk:
                    checks.append(
                        CheckResult(
                            service="ec2",
                            resource_id=volume_id,
                            resource_type="volume",
                            check_id="EC2-EBS-VOLUME-ENCRYPTED",
                            check_name="Attached EBS volume is encrypted",
                            status="ERROR",
                            severity="Medium",
                            cis_control="CIS 2.2.1",
                            message="Unable to inspect volume encryption state.",
                            details={"error": str(exc), "instance_id": volume_to_instance[volume_id]},
                        )
                    )
                continue

            for volume in volumes:
                volume_id = volume.get("VolumeId", "unknown-volume")
                instance_id = volume_to_instance.get(volume_id, "unknown-instance")
                encrypted = bool(volume.get("Encrypted", False))

                if encrypted:
                    checks.append(
                        CheckResult(
                            service="ec2",
                            resource_id=volume_id,
                            resource_type="volume",
                            check_id="EC2-EBS-VOLUME-ENCRYPTED",
                            check_name="Attached EBS volume is encrypted",
                            status="PASS",
                            severity="Medium",
                            cis_control="CIS 2.2.1",
                            message="Attached EBS volume is encrypted.",
                            details={"instance_id": instance_id},
                        )
                    )
                    continue

                severity = "Low" if ebs_default_enabled else "High"
                findings.append(
                    Finding(
                        service="ec2",
                        resource_id=volume_id,
                        title="Attached EBS volume is not encrypted",
                        description=(
                            f"Volume {volume_id} attached to instance {instance_id} is not encrypted."
                        ),
                        severity=severity,
                        cis_control="CIS 2.2.1",
                        remediation="Enable EBS encryption for this volume and snapshot/migrate as needed.",
                        details={"instance_id": instance_id, "encrypted": False},
                    )
                )
                checks.append(
                    CheckResult(
                        service="ec2",
                        resource_id=volume_id,
                        resource_type="volume",
                        check_id="EC2-EBS-VOLUME-ENCRYPTED",
                        check_name="Attached EBS volume is encrypted",
                        status="FAIL",
                        severity=severity,
                        cis_control="CIS 2.2.1",
                        message="Attached EBS volume is not encrypted.",
                        details={"instance_id": instance_id, "encrypted": False},
                    )
                )

    @staticmethod
    def _is_risky_port(from_port: int | None, to_port: int | None) -> bool:
        return from_port in {22, 3389} or to_port in {22, 3389}

    @staticmethod
    def _open_to_world(permission: dict) -> bool:
        for ip_range in permission.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                return True
        for ipv6_range in permission.get("Ipv6Ranges", []):
            if ipv6_range.get("CidrIpv6") == "::/0":
                return True
        return False

    @staticmethod
    def _permission_opens_all_traffic(permission: dict) -> bool:
        return permission.get("IpProtocol") == "-1" and EC2Scanner._open_to_world(permission)

    @staticmethod
    def _cis_control_for_port(port: int | None) -> str:
        if port == 22:
            return "CIS 5.1"
        if port == 3389:
            return "CIS 5.2"
        return "CIS 5.1"
