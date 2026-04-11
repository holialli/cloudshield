"""PDF reporting for CloudShield."""

from __future__ import annotations

from dataclasses import asdict
from typing import Dict, Iterable, List, Optional
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class PDFReporter:
    """Generate a concise security summary PDF."""

    def __init__(self, output_path: str) -> None:
        self.output_path = output_path

    def generate(
        self,
        findings: Iterable[object],
        checks: Optional[Iterable[object]] = None,
        scan_metadata: Optional[Dict[str, str]] = None,
    ) -> str:
        findings_list = [finding.to_dict() if hasattr(finding, "to_dict") else asdict(finding) for finding in findings]  # type: ignore[arg-type]
        checks_list = []
        if checks is not None:
            checks_list = [check.to_dict() if hasattr(check, "to_dict") else asdict(check) for check in checks]  # type: ignore[arg-type]
        risk_score = self._calculate_risk_score(checks_list)

        document = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )
        page_width = document.width
        styles = getSampleStyleSheet()
        cell_style = ParagraphStyle(
            "Cell",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
            wordWrap="CJK",
        )
        status_style = ParagraphStyle(
            "StatusCell",
            parent=cell_style,
            alignment=1,
        )
        elements: List[object] = []

        elements.append(Paragraph("CloudShield Security Summary", styles["Title"]))
        elements.append(Spacer(1, 12))
        if scan_metadata:
            target_rows = [
                ["Account ID", scan_metadata.get("account_id", "unknown")],
                ["Caller ARN", scan_metadata.get("caller_arn", "unknown")],
                ["Caller User ID", scan_metadata.get("caller_user_id", "unknown")],
                ["Region", scan_metadata.get("region", "unknown")],
                ["Scanned At (UTC)", scan_metadata.get("scanned_at_utc", "unknown")],
            ]
            elements.append(Paragraph("Scan Target Details", styles["Heading2"]))
            target_table = Table(
                [
                    [self._cell(row[0], cell_style), self._cell(row[1], cell_style)]
                    for row in target_rows
                ],
                colWidths=[page_width * 0.28, page_width * 0.72],
            )
            target_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e2e8f0")),
                        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            elements.append(target_table)
            elements.append(Spacer(1, 12))

        elements.append(
            Paragraph(f"Security Risk Score: <b>{risk_score}</b>/100", styles["Heading2"])
        )
        elements.append(
            Paragraph(
                "Risk score is derived from PASS/FAIL/ERROR outcomes across IAM, EC2, and S3 checks.",
                styles["BodyText"],
            )
        )
        elements.append(Spacer(1, 12))

        if checks_list:
            pass_count = sum(1 for check in checks_list if check.get("status") == "PASS")
            fail_count = sum(1 for check in checks_list if check.get("status") == "FAIL")
            error_count = sum(1 for check in checks_list if check.get("status") == "ERROR")
            exception_count = sum(
                1
                for check in checks_list
                if str(check.get("status", "")).upper() in {"EXCEPTION", "INFO"}
            )
            elements.append(
                Paragraph(
                    f"Checks: <b>{len(checks_list)}</b> total | PASS: <b>{pass_count}</b> | FAIL: <b>{fail_count}</b> | ERROR: <b>{error_count}</b> | EXCEPTION/INFO: <b>{exception_count}</b>",
                    styles["Normal"],
                )
            )
            elements.append(Spacer(1, 10))

            elements.append(Paragraph("Executive View: Pass vs Fail by Service", styles["Heading2"]))
            elements.append(self._service_status_chart(checks_list, page_width))
            elements.append(Spacer(1, 12))

            elements.append(Paragraph("Detailed Check Results By Service", styles["Heading2"]))
            for service in ("iam", "ec2", "s3"):
                service_checks = [
                    check
                    for check in checks_list
                    if str(check.get("service", "")).lower() == service
                ]
                elements.append(Paragraph(service.upper() + " Checks", styles["Heading3"]))
                if not service_checks:
                    elements.append(Paragraph("No checks were returned for this service.", styles["Normal"]))
                    elements.append(Spacer(1, 8))
                    continue

                check_rows = [
                    [
                        self._cell("Status", cell_style),
                        self._cell("Type", cell_style),
                        self._cell("Resource", cell_style),
                        self._cell("Check", cell_style),
                        self._cell("CIS", cell_style),
                        self._cell("Severity", cell_style),
                        self._cell("Details", cell_style),
                    ]
                ]
                for check in service_checks:
                    check_rows.append(
                        [
                            self._status_cell(check.get("status", "UNKNOWN"), status_style),
                            self._cell(check.get("resource_type", "unknown"), cell_style),
                            self._cell(check.get("resource_id", "unknown"), cell_style),
                            self._cell(
                                check.get("check_name", check.get("check_id", "check")),
                                cell_style,
                            ),
                            self._cell(check.get("cis_control", "N/A"), cell_style),
                            self._cell(check.get("severity", "Unknown"), cell_style),
                            self._cell(check.get("message", ""), cell_style),
                        ]
                    )

                check_table = Table(
                    check_rows,
                    repeatRows=1,
                    colWidths=[
                        page_width * 0.08,
                        page_width * 0.10,
                        page_width * 0.17,
                        page_width * 0.22,
                        page_width * 0.10,
                        page_width * 0.10,
                        page_width * 0.23,
                    ],
                )
                check_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d4ed8")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),
                        ]
                    )
                )
                elements.append(check_table)
                elements.append(Spacer(1, 10))

            action_rows = [
                [
                    self._cell("Service", cell_style),
                    self._cell("Resource", cell_style),
                    self._cell("Failed Check", cell_style),
                    self._cell("Recommended Command", cell_style),
                    self._cell("Reference", cell_style),
                ]
            ]
            for check in checks_list:
                status = str(check.get("status", "")).upper()
                if status not in {"FAIL", "ERROR"}:
                    continue
                command, reference = self._remediation_for_check(str(check.get("check_id", "")))
                action_rows.append(
                    [
                        self._cell(check.get("service", "unknown"), cell_style),
                        self._cell(check.get("resource_id", "unknown"), cell_style),
                        self._cell(check.get("check_name", check.get("check_id", "check")), cell_style),
                        self._cell(command, cell_style),
                        self._cell(reference, cell_style),
                    ]
                )

            if len(action_rows) > 1:
                remediation_table = Table(
                    action_rows,
                    repeatRows=1,
                    colWidths=[
                        page_width * 0.08,
                        page_width * 0.17,
                        page_width * 0.25,
                        page_width * 0.28,
                        page_width * 0.22,
                    ],
                )
                remediation_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7c2d12")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),
                        ]
                    )
                )
                elements.append(Paragraph("Remediation Next Steps", styles["Heading2"]))
                elements.append(remediation_table)
                elements.append(Spacer(1, 10))

        summary_rows = [["Service", "CIS Control", "Severity", "Resource", "Title"]]
        for finding in findings_list:
            summary_rows.append(
                [
                    self._cell(finding.get("service", "unknown"), cell_style),
                    self._cell(finding.get("cis_control", "N/A"), cell_style),
                    self._cell(finding.get("severity", "Unknown"), cell_style),
                    self._cell(finding.get("resource_id", "Unknown"), cell_style),
                    self._cell(finding.get("title", "Finding"), cell_style),
                ]
            )

        table = Table(
            summary_rows,
            repeatRows=1,
            colWidths=[
                page_width * 0.12,
                page_width * 0.12,
                page_width * 0.10,
                page_width * 0.24,
                page_width * 0.42,
            ],
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),
                ]
            )
        )
        elements.append(Paragraph("Failed Findings", styles["Heading2"]))
        elements.append(table)
        document.build(elements)
        return self.output_path

    @staticmethod
    def _cell(value: object, style: ParagraphStyle) -> Paragraph:
        text = escape(str(value))
        return Paragraph(text, style)

    @staticmethod
    def _status_cell(status: object, style: ParagraphStyle) -> Paragraph:
        status_text = str(status).upper()
        color_map = {
            "PASS": "#166534",
            "FAIL": "#991b1b",
            "ERROR": "#92400e",
            "EXCEPTION": "#1d4ed8",
            "INFO": "#1f2937",
        }
        color = color_map.get(status_text, "#1f2937")
        return Paragraph(f'<font color="{color}"><b>{escape(status_text)}</b></font>', style)

    @staticmethod
    def _calculate_risk_score(checks: List[dict]) -> int:
        if not checks:
            return 100

        severity_weights = {
            "CRITICAL": 10,
            "HIGH": 10,
            "MEDIUM": 5,
            "LOW": 2,
            "INFORMATIONAL": 0,
        }
        score = 100.0
        grouped: Dict[tuple[str, str], Dict[str, float]] = {}

        for check in checks:
            severity = str(check.get("severity", "Low")).upper()
            weight = float(severity_weights.get(severity, 2))
            if weight == 0:
                continue

            status = str(check.get("status", "ERROR")).upper()
            if status in {"EXCEPTION", "INFO", "PASS"}:
                continue

            key = (
                str(check.get("service", "unknown")).lower(),
                str(check.get("check_id", "unknown")),
            )
            bucket = grouped.setdefault(key, {"weight": weight, "fail": 0.0, "error": 0.0})
            bucket["weight"] = max(bucket["weight"], weight)

            if status == "FAIL":
                bucket["fail"] += 1
            elif status == "ERROR":
                bucket["error"] += 1

        for values in grouped.values():
            weight = values["weight"]
            fail_count = values["fail"]
            error_count = values["error"]

            # First occurrence uses full weight; repeats are discounted and capped.
            fail_penalty = 0.0
            if fail_count > 0:
                fail_penalty = weight + max(0.0, fail_count - 1) * (weight * 0.25)
                fail_penalty = min(fail_penalty, weight * 2.0)

            error_penalty = 0.0
            if error_count > 0:
                error_penalty = (weight * 0.5) + max(0.0, error_count - 1) * (weight * 0.1)
                error_penalty = min(error_penalty, weight)

            score -= fail_penalty + error_penalty

        return max(0, min(100, int(round(score))))

    @staticmethod
    def _service_status_chart(checks: List[dict], page_width: float) -> Drawing:
        services = ["iam", "ec2", "s3"]
        pass_counts = []
        fail_counts = []

        for service in services:
            service_checks = [
                check for check in checks if str(check.get("service", "")).lower() == service
            ]
            pass_counts.append(
                sum(1 for check in service_checks if str(check.get("status", "")).upper() == "PASS")
            )
            fail_counts.append(
                sum(1 for check in service_checks if str(check.get("status", "")).upper() == "FAIL")
            )

        drawing = Drawing(page_width, 170)
        chart = VerticalBarChart()
        chart.x = 40
        chart.y = 40
        chart.height = 105
        chart.width = page_width - 80
        chart.data = [pass_counts, fail_counts]
        chart.categoryAxis.categoryNames = [service.upper() for service in services]
        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueMax = max(1, max(pass_counts + fail_counts) + 1)
        chart.valueAxis.valueStep = max(1, int(chart.valueAxis.valueMax / 5))
        chart.bars[0].fillColor = colors.HexColor("#166534")
        chart.bars[1].fillColor = colors.HexColor("#991b1b")
        drawing.add(chart)
        drawing.add(String(45, 150, "Pass", fontSize=8, fillColor=colors.HexColor("#166534")))
        drawing.add(String(95, 150, "Fail", fontSize=8, fillColor=colors.HexColor("#991b1b")))
        return drawing

    @staticmethod
    def _remediation_for_check(check_id: str) -> tuple[str, str]:
        mapping: Dict[str, tuple[str, str]] = {
            "EC2-EBS-ENCRYPTION-BY-DEFAULT": (
                "aws ec2 enable-ebs-encryption-by-default",
                "https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html",
            ),
            "EC2-EBS-VOLUME-ENCRYPTED": (
                "aws ec2 create-snapshot ; copy encrypted snapshot ; recreate volume",
                "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html",
            ),
            "EC2-IMDSV2-REQUIRED": (
                "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required",
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
            ),
            "EC2-NO-PUBLIC-IP": (
                "aws ec2 modify-network-interface-attribute --network-interface-id <eni> --no-associate-public-ip-address",
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
            ),
            "S3-ACCOUNT-PUBLIC-ACCESS-BLOCK": (
                "aws s3control put-public-access-block --account-id <id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            ),
            "S3-PUBLIC-ACCESS-BLOCK": (
                "aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            ),
            "IAM-ROOT-MFA": (
                "Enable MFA on root account in AWS console (root user only)",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_mfa.html",
            ),
            "IAM-USER-KEY-AGE": (
                "aws iam update-access-key --user-name <user> --access-key-id <id> --status Inactive",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            ),
            "IAM-POLICY-WILDCARD": (
                "Refactor IAM policy to replace Action/Resource '*' with scoped values",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            ),
            "IAM-ROLE-WILDCARD": (
                "Refactor role policies to least privilege (exclude AWS service-linked role exceptions)",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            ),
        }
        return mapping.get(
            check_id,
            (
                "Review resource and apply least-privilege hardening for this check.",
                "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html",
            ),
        )
