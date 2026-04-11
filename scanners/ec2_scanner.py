"""EC2 security group scanner for CloudShield."""

from __future__ import annotations

from typing import List

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanners.iam_scanner import Finding


class EC2Scanner:
    """Scan security groups for risky inbound SSH/RDP exposure."""

    def __init__(self, session: boto3.Session) -> None:
        self.ec2 = session.client("ec2")

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            security_groups = self.ec2.describe_security_groups().get(
                "SecurityGroups", []
            )
        except (BotoCoreError, ClientError) as exc:
            return [
                Finding(
                    service="ec2",
                    resource_id="security-groups",
                    title="Unable to list security groups",
                    description=str(exc),
                    severity="Medium",
                    cis_control="CIS 5.1",
                    remediation="Review EC2 permissions and API access.",
                    details={"error": str(exc)},
                )
            ]

        for security_group in security_groups:
            group_id = security_group.get("GroupId", "unknown")
            group_name = security_group.get("GroupName", group_id)
            for permission in security_group.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                if not self._is_risky_port(from_port, to_port):
                    continue

                if self._open_to_world(permission):
                    findings.append(
                        Finding(
                            service="ec2",
                            resource_id=group_id,
                            title="Security group allows risky public ingress",
                            description=(
                                f"Security group {group_name} exposes port {from_port} to 0.0.0.0/0."
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

        return findings

    @staticmethod
    def _is_risky_port(from_port: int | None, to_port: int | None) -> bool:
        return from_port in {22, 3389} or to_port in {22, 3389}

    @staticmethod
    def _open_to_world(permission: dict) -> bool:
        for ip_range in permission.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                return True
        return False

    @staticmethod
    def _cis_control_for_port(port: int | None) -> str:
        if port == 22:
            return "CIS 5.1"
        if port == 3389:
            return "CIS 5.2"
        return "CIS 5.1"
