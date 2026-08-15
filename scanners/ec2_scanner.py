"""EC2 security group and instance scanner for CloudShield."""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from core.awsutil import BOTO_CONFIG, paginate
from core.models import (
    STATUS_FAIL,
    STATUS_PASS,
    CheckResult,
    Finding,
    error_check,
)

#: Ports we call out by name. Any rule whose port *range* covers one of these
#: counts -- ``0-65535`` includes 22 just as much as ``22-22`` does.
RISKY_PORTS: Dict[int, str] = {22: "SSH", 3389: "RDP"}

#: A prefix this short is effectively "the internet" even if it is not /0.
BROAD_IPV4_PREFIX = 8
BROAD_IPV6_PREFIX = 32


class EC2Scanner:
    """Scan EC2 in a single region for risky exposure and weak hardening."""

    service = "ec2"

    def __init__(self, session: boto3.Session, region: Optional[str] = None) -> None:
        self.region = region or session.region_name or "us-east-1"
        self.ec2 = session.client("ec2", region_name=self.region, config=BOTO_CONFIG)

    def scan(self) -> List[Finding]:
        findings, _ = self.scan_detailed()
        return findings

    def scan_detailed(self) -> Tuple[List[Finding], List[CheckResult]]:
        findings: List[Finding] = []
        checks: List[CheckResult] = []

        ebs_default_enabled = self._scan_ebs_encryption_default(findings, checks)
        self._scan_security_groups(findings, checks)
        self._scan_instances(findings, checks, ebs_default_enabled)

        return findings, checks

    def _check(self, **kwargs) -> CheckResult:
        kwargs.setdefault("region", self.region)
        return CheckResult(service="ec2", **kwargs)

    def _finding(self, **kwargs) -> Finding:
        kwargs.setdefault("region", self.region)
        return Finding(service="ec2", **kwargs)

    # ------------------------------------------------------------------
    # Security groups
    # ------------------------------------------------------------------

    def _scan_security_groups(
        self, findings: List[Finding], checks: List[CheckResult]
    ) -> None:
        try:
            security_groups = list(
                paginate(self.ec2, "describe_security_groups", "SecurityGroups")
            )
        except (BotoCoreError, ClientError) as exc:
            checks.append(
                error_check(
                    service="ec2",
                    resource_id="security-groups",
                    resource_type="collection",
                    check_id="EC2-SG-LIST",
                    check_name="EC2 security groups can be listed",
                    message="Unable to list security groups.",
                    error=exc,
                    cis_control="CIS 5.2",
                    region=self.region,
                )
            )
            return

        for security_group in security_groups:
            self._scan_security_group(security_group, findings, checks)

    def _scan_security_group(
        self,
        security_group: dict,
        findings: List[Finding],
        checks: List[CheckResult],
    ) -> None:
        group_id = security_group.get("GroupId", "unknown")
        group_name = security_group.get("GroupName", group_id)
        vpc_id = security_group.get("VpcId", "")
        base_details = {"group_id": group_id, "group_name": group_name, "vpc_id": vpc_id}

        risky_rules: List[dict] = []
        open_all_rules: List[dict] = []
        exposed_ports: List[int] = []

        for permission in security_group.get("IpPermissions", []):
            sources = self._public_sources(permission)
            if not sources:
                continue

            protocol = str(permission.get("IpProtocol", "-1"))
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")
            rule = {
                "protocol": protocol,
                "from_port": from_port,
                "to_port": to_port,
                "sources": sources,
            }

            if protocol == "-1":
                open_all_rules.append(rule)
                # Protocol -1 covers every port, so it also exposes SSH and RDP.
                covered = sorted(RISKY_PORTS)
            else:
                covered = self._covered_risky_ports(protocol, from_port, to_port)

            if covered:
                exposed_ports.extend(covered)
                risky_rules.append({**rule, "exposed_ports": covered})

        if risky_rules:
            exposed_ports = sorted(set(exposed_ports))
            names = ", ".join(RISKY_PORTS[port] for port in exposed_ports)
            cis_control = self._cis_for_rules(risky_rules)
            findings.append(
                self._finding(
                    resource_id=group_id,
                    title="Security group allows risky public ingress",
                    description=(
                        f"Security group {group_name} exposes {names} "
                        f"(port(s) {', '.join(str(p) for p in exposed_ports)}) to the public internet."
                    ),
                    severity="High",
                    cis_control=cis_control,
                    remediation=(
                        "Restrict inbound access to trusted IP ranges or use a VPN/bastion host."
                    ),
                    details={**base_details, "risky_rules": risky_rules, "exposed_ports": exposed_ports},
                    check_id="EC2-SG-RISKY-PUBLIC-INGRESS",
                )
            )
            checks.append(
                self._check(
                    resource_id=group_id,
                    resource_type="security-group",
                    check_id="EC2-SG-RISKY-PUBLIC-INGRESS",
                    check_name="Security group blocks public SSH/RDP ingress",
                    status=STATUS_FAIL,
                    severity="High",
                    cis_control=cis_control,
                    message=f"Security group exposes {names} to the public internet.",
                    details={**base_details, "risky_rules": risky_rules, "exposed_ports": exposed_ports},
                )
            )
        else:
            checks.append(
                self._check(
                    resource_id=group_id,
                    resource_type="security-group",
                    check_id="EC2-SG-RISKY-PUBLIC-INGRESS",
                    check_name="Security group blocks public SSH/RDP ingress",
                    status=STATUS_PASS,
                    severity="High",
                    cis_control="CIS 5.2",
                    message="Security group has no public SSH/RDP exposure.",
                    details=base_details,
                )
            )

        all_traffic_cis = self._cis_for_rules(open_all_rules)
        if open_all_rules:
            findings.append(
                self._finding(
                    resource_id=group_id,
                    title="Security group allows all traffic from the internet",
                    description=f"Security group {group_name} has protocol -1 open to the world.",
                    severity="High",
                    cis_control=all_traffic_cis,
                    remediation="Remove broad public ingress and scope protocol/ports to trusted networks.",
                    details={**base_details, "open_all_rules": open_all_rules},
                    check_id="EC2-SG-NO-ALL-TRAFFIC",
                )
            )
        checks.append(
            self._check(
                resource_id=group_id,
                resource_type="security-group",
                check_id="EC2-SG-NO-ALL-TRAFFIC",
                check_name="Security group blocks public all-traffic ingress",
                status=STATUS_FAIL if open_all_rules else STATUS_PASS,
                severity="High",
                cis_control=all_traffic_cis,
                message=(
                    "Security group allows all protocols from the public internet."
                    if open_all_rules
                    else "Security group does not allow all-protocol public ingress."
                ),
                details={**base_details, "open_all_rules": open_all_rules},
            )
        )

        if group_name == "default":
            self._scan_default_security_group(security_group, base_details, findings, checks)

    def _scan_default_security_group(
        self,
        security_group: dict,
        base_details: dict,
        findings: List[Finding],
        checks: List[CheckResult],
    ) -> None:
        group_id = base_details["group_id"]
        # CIS 5.4 wants the default SG to carry no rules at all.
        ingress_rules = security_group.get("IpPermissions", []) or []
        egress_rules = security_group.get("IpPermissionsEgress", []) or []
        has_rules = bool(ingress_rules or egress_rules)
        details = {
            **base_details,
            "ingress_rule_count": len(ingress_rules),
            "egress_rule_count": len(egress_rules),
        }

        if has_rules:
            findings.append(
                self._finding(
                    resource_id=group_id,
                    title="Default security group is not empty",
                    description="The default security group should restrict all traffic.",
                    severity="Medium",
                    cis_control="CIS 5.4",
                    remediation="Remove all ingress and egress rules from the default security group.",
                    details=details,
                    check_id="EC2-DEFAULT-SG-HARDENED",
                )
            )
        checks.append(
            self._check(
                resource_id=group_id,
                resource_type="security-group",
                check_id="EC2-DEFAULT-SG-HARDENED",
                check_name="Default security group restricts all traffic",
                status=STATUS_FAIL if has_rules else STATUS_PASS,
                severity="Medium",
                cis_control="CIS 5.4",
                message=(
                    f"Default security group has {len(ingress_rules)} ingress and "
                    f"{len(egress_rules)} egress rule(s)."
                    if has_rules
                    else "Default security group has no rules."
                ),
                details=details,
            )
        )

    # ------------------------------------------------------------------
    # EBS encryption defaults
    # ------------------------------------------------------------------

    def _scan_ebs_encryption_default(
        self, findings: List[Finding], checks: List[CheckResult]
    ) -> bool:
        try:
            enabled = bool(
                self.ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
            )
        except (BotoCoreError, ClientError) as exc:
            checks.append(
                error_check(
                    service="ec2",
                    resource_id="account-ebs-encryption",
                    resource_type="account",
                    check_id="EC2-EBS-ENCRYPTION-BY-DEFAULT",
                    check_name="EBS encryption by default is enabled",
                    message="Unable to evaluate account-level EBS encryption default.",
                    error=exc,
                    cis_control="CIS 2.2.1",
                    region=self.region,
                )
            )
            return False

        checks.append(
            self._check(
                resource_id="account-ebs-encryption",
                resource_type="account",
                check_id="EC2-EBS-ENCRYPTION-BY-DEFAULT",
                check_name="EBS encryption by default is enabled",
                status=STATUS_PASS if enabled else STATUS_FAIL,
                severity="Medium",
                cis_control="CIS 2.2.1",
                message=(
                    f"EBS encryption by default is enabled in {self.region}."
                    if enabled
                    else f"EBS encryption by default is disabled in {self.region}."
                ),
                details={"ebs_encryption_by_default": enabled},
            )
        )
        if not enabled:
            findings.append(
                self._finding(
                    resource_id="account-ebs-encryption",
                    title="EBS encryption by default is disabled",
                    description="New EBS volumes may be created unencrypted by default.",
                    severity="Medium",
                    cis_control="CIS 2.2.1",
                    remediation="Enable EBS encryption by default for this AWS region.",
                    details={"ebs_encryption_by_default": False},
                    check_id="EC2-EBS-ENCRYPTION-BY-DEFAULT",
                )
            )
        return enabled

    # ------------------------------------------------------------------
    # Instances and volumes
    # ------------------------------------------------------------------

    def _scan_instances(
        self,
        findings: List[Finding],
        checks: List[CheckResult],
        ebs_default_enabled: bool,
    ) -> None:
        try:
            reservations = list(paginate(self.ec2, "describe_instances", "Reservations"))
        except (BotoCoreError, ClientError) as exc:
            checks.append(
                error_check(
                    service="ec2",
                    resource_id="instances",
                    resource_type="collection",
                    check_id="EC2-INSTANCE-LIST",
                    check_name="EC2 instances can be listed",
                    message="Unable to list EC2 instances.",
                    error=exc,
                    cis_control="CIS 5.6",
                    region=self.region,
                )
            )
            return

        volume_to_instance: Dict[str, str] = {}
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId", "unknown-instance")
                if instance.get("State", {}).get("Name") == "terminated":
                    continue

                self._check_imdsv2(instance, instance_id, findings, checks)
                self._check_public_ip(instance, instance_id, findings, checks)

                for mapping in instance.get("BlockDeviceMappings", []):
                    volume_id = mapping.get("Ebs", {}).get("VolumeId")
                    if volume_id:
                        volume_to_instance[volume_id] = instance_id

        self._scan_volume_encryption(findings, checks, volume_to_instance, ebs_default_enabled)

    def _check_imdsv2(
        self,
        instance: dict,
        instance_id: str,
        findings: List[Finding],
        checks: List[CheckResult],
    ) -> None:
        http_tokens = instance.get("MetadataOptions", {}).get("HttpTokens", "optional")
        required = http_tokens == "required"
        details = {"instance_id": instance_id, "http_tokens": http_tokens}

        checks.append(
            self._check(
                resource_id=instance_id,
                resource_type="instance",
                check_id="EC2-IMDSV2-REQUIRED",
                check_name="EC2 instance requires IMDSv2",
                status=STATUS_PASS if required else STATUS_FAIL,
                severity="High",
                cis_control="CIS 5.6",
                message=(
                    "IMDSv2 is required for this instance."
                    if required
                    else "IMDSv2 is not required for this instance."
                ),
                details=details,
            )
        )
        if not required:
            findings.append(
                self._finding(
                    resource_id=instance_id,
                    title="EC2 instance does not require IMDSv2",
                    description="Instance metadata service v2 enforcement is not enabled.",
                    severity="High",
                    cis_control="CIS 5.6",
                    remediation="Set instance metadata options HttpTokens to required.",
                    details=details,
                    check_id="EC2-IMDSV2-REQUIRED",
                )
            )

    def _check_public_ip(
        self,
        instance: dict,
        instance_id: str,
        findings: List[Finding],
        checks: List[CheckResult],
    ) -> None:
        public_ip = instance.get("PublicIpAddress")
        if not public_ip:
            for interface in instance.get("NetworkInterfaces", []):
                public_ip = interface.get("Association", {}).get("PublicIp")
                if public_ip:
                    break

        details = {"instance_id": instance_id, "public_ip": public_ip}
        checks.append(
            self._check(
                resource_id=instance_id,
                resource_type="instance",
                check_id="EC2-NO-PUBLIC-IP",
                check_name="EC2 instance avoids public IP exposure",
                status=STATUS_FAIL if public_ip else STATUS_PASS,
                severity="Medium",
                cis_control="FSBP EC2.9",
                message=(
                    "Instance has a public IP address."
                    if public_ip
                    else "Instance has no public IP address."
                ),
                details=details,
            )
        )
        if public_ip:
            findings.append(
                self._finding(
                    resource_id=instance_id,
                    title="EC2 instance has a public IP address",
                    description="Instance is directly internet-addressable.",
                    severity="Medium",
                    cis_control="FSBP EC2.9",
                    remediation="Place the instance in a private subnet or restrict inbound exposure.",
                    details=details,
                    check_id="EC2-NO-PUBLIC-IP",
                )
            )

    def _scan_volume_encryption(
        self,
        findings: List[Finding],
        checks: List[CheckResult],
        volume_to_instance: Dict[str, str],
        ebs_default_enabled: bool,
    ) -> None:
        if not volume_to_instance:
            return

        volume_ids = list(volume_to_instance)
        for start in range(0, len(volume_ids), 200):
            chunk = volume_ids[start : start + 200]
            try:
                volumes = list(
                    paginate(self.ec2, "describe_volumes", "Volumes", VolumeIds=chunk)
                )
            except (BotoCoreError, ClientError) as exc:
                for volume_id in chunk:
                    checks.append(
                        error_check(
                            service="ec2",
                            resource_id=volume_id,
                            resource_type="volume",
                            check_id="EC2-EBS-VOLUME-ENCRYPTED",
                            check_name="Attached EBS volume is encrypted",
                            message="Unable to inspect volume encryption state.",
                            error=exc,
                            cis_control="CIS 2.2.1",
                            region=self.region,
                            details={"instance_id": volume_to_instance[volume_id]},
                        )
                    )
                continue

            for volume in volumes:
                volume_id = volume.get("VolumeId", "unknown-volume")
                instance_id = volume_to_instance.get(volume_id, "unknown-instance")
                encrypted = bool(volume.get("Encrypted", False))
                # If the account default is on, an unencrypted volume is legacy
                # drift rather than an ongoing exposure of new data.
                severity = "Low" if ebs_default_enabled else "High"
                details = {
                    "instance_id": instance_id,
                    "volume_id": volume_id,
                    "encrypted": encrypted,
                }

                checks.append(
                    self._check(
                        resource_id=volume_id,
                        resource_type="volume",
                        check_id="EC2-EBS-VOLUME-ENCRYPTED",
                        check_name="Attached EBS volume is encrypted",
                        status=STATUS_PASS if encrypted else STATUS_FAIL,
                        severity="Medium" if encrypted else severity,
                        cis_control="CIS 2.2.1",
                        message=(
                            "Attached EBS volume is encrypted."
                            if encrypted
                            else "Attached EBS volume is not encrypted."
                        ),
                        details=details,
                    )
                )
                if not encrypted:
                    findings.append(
                        self._finding(
                            resource_id=volume_id,
                            title="Attached EBS volume is not encrypted",
                            description=(
                                f"Volume {volume_id} attached to instance {instance_id} is not encrypted."
                            ),
                            severity=severity,
                            cis_control="CIS 2.2.1",
                            remediation="Snapshot the volume, copy the snapshot with encryption, and replace it.",
                            details=details,
                            check_id="EC2-EBS-VOLUME-ENCRYPTED",
                        )
                    )

    # ------------------------------------------------------------------
    # Rule helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cis_for_rules(rules: List[dict]) -> str:
        """CIS v3.0 splits admin-port ingress by IP family: 5.2 IPv4, 5.3 IPv6."""

        if not rules:
            return "CIS 5.2"
        has_ipv4 = any(
            ":" not in source for rule in rules for source in rule.get("sources", [])
        )
        return "CIS 5.2" if has_ipv4 else "CIS 5.3"

    @staticmethod
    def _covered_risky_ports(
        protocol: str, from_port: Optional[int], to_port: Optional[int]
    ) -> List[int]:
        """Return the risky ports contained in this rule's port *range*.

        A rule of ``tcp 0-65535`` exposes SSH just as surely as ``tcp 22-22``;
        matching the endpoints exactly missed every broad range.
        """

        if protocol not in {"tcp", "6", "-1"}:
            return []
        if from_port is None or to_port is None:
            # No port range on a non-"-1" protocol means all ports.
            return sorted(RISKY_PORTS)

        low, high = min(from_port, to_port), max(from_port, to_port)
        return [port for port in sorted(RISKY_PORTS) if low <= port <= high]

    @staticmethod
    def _public_sources(permission: dict) -> List[str]:
        """Return the internet-facing CIDRs in a rule.

        Anything at or below a /8 (IPv4) or /32 (IPv6) prefix is treated as
        public: ``0.0.0.0/1`` is not ``0.0.0.0/0``, but it is not a trusted
        allowlist either.
        """

        sources: List[str] = []

        for ip_range in permission.get("IpRanges", []) or []:
            cidr = ip_range.get("CidrIp")
            if not cidr:
                continue
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if network.prefixlen <= BROAD_IPV4_PREFIX:
                sources.append(cidr)

        for ipv6_range in permission.get("Ipv6Ranges", []) or []:
            cidr = ipv6_range.get("CidrIpv6")
            if not cidr:
                continue
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if network.prefixlen <= BROAD_IPV6_PREFIX:
                sources.append(cidr)

        return sources
