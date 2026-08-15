"""PDF reporting for CloudShield."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
from typing import Dict, Iterable, List, Optional, Sequence
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.models import CheckResult
from remediators import registry

#: Above this many PASS rows for a single check id we print a count instead of
#: every row. Without it, a paginated scan of a large account produces a
#: thousand-page PDF nobody reads.
MAX_PASS_ROWS_PER_CHECK = 10

STATUS_COLORS = {
    "PASS": "#166534",
    "FAIL": "#991b1b",
    "ERROR": "#92400e",
    "EXCEPTION": "#1d4ed8",
    "INFO": "#1f2937",
    "SUPPRESSED": "#6d28d9",
}


class PDFReporter:
    """Generate a concise security summary PDF."""

    def __init__(self, output_path: str) -> None:
        self.output_path = output_path

    # ------------------------------------------------------------------

    def generate(
        self,
        findings: Iterable[object],
        checks: Optional[Iterable[object]] = None,
        scan_metadata: Optional[Dict[str, str]] = None,
        remediations: Optional[Sequence[Dict[str, object]]] = None,
    ) -> str:
        findings_list = [_as_dict(finding) for finding in findings]
        check_objects: List[CheckResult] = list(checks or [])  # type: ignore[arg-type]
        checks_list = [_as_dict(check) for check in check_objects]
        risk_score = self._calculate_risk_score(checks_list)

        document = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
            title="CloudShield Security Summary",
        )
        page_width = document.width
        styles = getSampleStyleSheet()
        cell = ParagraphStyle(
            "Cell", parent=styles["BodyText"], fontSize=8, leading=10, wordWrap="CJK"
        )
        status_style = ParagraphStyle("StatusCell", parent=cell, alignment=1)
        elements: List[object] = []

        elements.append(Paragraph("CloudShield Security Summary", styles["Title"]))
        elements.append(Spacer(1, 12))

        if scan_metadata:
            elements.extend(self._target_section(scan_metadata, page_width, cell, styles))

        elements.extend(
            self._score_section(risk_score, checks_list, page_width, styles)
        )
        if checks_list:
            elements.extend(
                self._detail_sections(checks_list, page_width, cell, status_style, styles)
            )
            elements.extend(
                self._remediation_section(check_objects, page_width, cell, styles)
            )
        if remediations:
            elements.extend(
                self._applied_section(remediations, page_width, cell, styles)
            )
        elements.extend(self._findings_section(findings_list, page_width, cell, styles))

        document.build(elements)
        return self.output_path

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _target_section(self, metadata, page_width, cell, styles) -> List[object]:
        rows = [
            ["Account ID", metadata.get("account_id", "unknown")],
            ["Caller ARN", metadata.get("caller_arn", "unknown")],
            ["Caller User ID", metadata.get("caller_user_id", "unknown")],
            ["Regions Scanned", metadata.get("regions", metadata.get("region", "unknown"))],
            ["Scanned At (UTC)", metadata.get("scanned_at_utc", "unknown")],
            ["Mode", metadata.get("mode", "read-only scan")],
        ]
        table = Table(
            [[self._cell(row[0], cell), self._cell(row[1], cell)] for row in rows],
            colWidths=[page_width * 0.28, page_width * 0.72],
        )
        table.setStyle(
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
        return [Paragraph("Scan Target Details", styles["Heading2"]), table, Spacer(1, 12)]

    def _score_section(self, risk_score, checks_list, page_width, styles) -> List[object]:
        elements: List[object] = [
            Paragraph(f"Security Risk Score: <b>{risk_score}</b>/100", styles["Heading2"]),
            Paragraph(
                "Risk score is derived from PASS/FAIL/ERROR outcomes across IAM, EC2 and S3 "
                "checks. Suppressed (accepted-risk) results do not affect the score.",
                styles["BodyText"],
            ),
            Spacer(1, 12),
        ]
        if not checks_list:
            return elements

        counts = Counter(_display_status(check) for check in checks_list)
        elements.append(
            Paragraph(
                f"Checks: <b>{len(checks_list)}</b> total | "
                f"PASS: <b>{counts['PASS']}</b> | FAIL: <b>{counts['FAIL']}</b> | "
                f"ERROR: <b>{counts['ERROR']}</b> | "
                f"SUPPRESSED: <b>{counts['SUPPRESSED']}</b> | "
                f"EXCEPTION/INFO: <b>{counts['EXCEPTION'] + counts['INFO']}</b>",
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 10))
        elements.append(
            Paragraph("Executive View: Pass vs Fail by Service", styles["Heading2"])
        )
        elements.append(self._service_status_chart(checks_list, page_width))
        elements.append(Spacer(1, 12))
        return elements

    def _detail_sections(
        self, checks_list, page_width, cell, status_style, styles
    ) -> List[object]:
        elements: List[object] = [
            Paragraph("Detailed Check Results By Service", styles["Heading2"])
        ]

        for service in ("iam", "ec2", "s3"):
            service_checks = [
                check
                for check in checks_list
                if str(check.get("service", "")).lower() == service
            ]
            elements.append(Paragraph(f"{service.upper()} Checks", styles["Heading3"]))
            if not service_checks:
                elements.append(
                    Paragraph("No checks were returned for this service.", styles["Normal"])
                )
                elements.append(Spacer(1, 8))
                continue

            shown, collapsed = self._collapse_passes(service_checks)
            rows = [
                [
                    self._cell(header, cell)
                    for header in (
                        "Status",
                        "Region",
                        "Type",
                        "Resource",
                        "Check",
                        "CIS",
                        "Severity",
                        "Details",
                    )
                ]
            ]
            for check in shown:
                rows.append(
                    [
                        self._status_cell(check, status_style),
                        self._cell(check.get("region", "global"), cell),
                        self._cell(check.get("resource_type", "unknown"), cell),
                        self._cell(check.get("resource_id", "unknown"), cell),
                        self._cell(
                            check.get("check_name", check.get("check_id", "check")), cell
                        ),
                        self._cell(check.get("cis_control", "N/A"), cell),
                        self._cell(check.get("severity", "Unknown"), cell),
                        self._cell(_detail_text(check), cell),
                    ]
                )

            table = Table(
                rows,
                repeatRows=1,
                colWidths=[
                    page_width * 0.09,
                    page_width * 0.10,
                    page_width * 0.09,
                    page_width * 0.15,
                    page_width * 0.18,
                    page_width * 0.08,
                    page_width * 0.09,
                    page_width * 0.22,
                ],
            )
            table.setStyle(self._table_style("#1d4ed8"))
            elements.append(table)
            if collapsed:
                elements.append(Spacer(1, 4))
                elements.append(
                    Paragraph(
                        "Passing results collapsed for brevity: "
                        + "; ".join(
                            f"{check_id} +{count} more passed"
                            for check_id, count in sorted(collapsed.items())
                        )
                        + ". Full detail is in the JSON results.",
                        styles["Normal"],
                    )
                )
            elements.append(Spacer(1, 10))

        return elements

    def _remediation_section(
        self, check_objects: List[CheckResult], page_width, cell, styles
    ) -> List[object]:
        rows = [
            [
                self._cell(header, cell)
                for header in (
                    "Service",
                    "Region",
                    "Resource",
                    "Failed Check",
                    "Recommended Action",
                    "Command",
                    "Auto",
                )
            ]
        ]
        for check in check_objects:
            if check.status not in {"FAIL", "ERROR"} or check.suppressed:
                continue
            description, command, doc_url = registry.describe(check)
            remediation = registry.lookup(check.check_id)
            auto = "no"
            if remediation and remediation.automated:
                auto = "yes (destructive)" if remediation.destructive else "yes"
            rows.append(
                [
                    self._cell(check.service, cell),
                    self._cell(check.region, cell),
                    self._cell(check.resource_id, cell),
                    self._cell(check.check_name or check.check_id, cell),
                    self._cell(f"{description} Ref: {doc_url}", cell),
                    self._cell(command or "-", cell),
                    self._cell(auto, cell),
                ]
            )

        if len(rows) == 1:
            return []

        table = Table(
            rows,
            repeatRows=1,
            colWidths=[
                page_width * 0.07,
                page_width * 0.09,
                page_width * 0.15,
                page_width * 0.17,
                page_width * 0.24,
                page_width * 0.19,
                page_width * 0.09,
            ],
        )
        table.setStyle(self._table_style("#7c2d12"))
        return [
            Paragraph("Remediation Next Steps", styles["Heading2"]),
            table,
            Spacer(1, 10),
        ]

    def _applied_section(self, remediations, page_width, cell, styles) -> List[object]:
        rows = [
            [
                self._cell(header, cell)
                for header in ("Status", "Check", "Region", "Resource", "Result")
            ]
        ]
        for item in remediations:
            rows.append(
                [
                    self._cell(str(item.get("status", "")).upper(), cell),
                    self._cell(item.get("check_id", ""), cell),
                    self._cell(item.get("region", ""), cell),
                    self._cell(item.get("resource_id", ""), cell),
                    self._cell(item.get("message", ""), cell),
                ]
            )
        table = Table(
            rows,
            repeatRows=1,
            colWidths=[
                page_width * 0.12,
                page_width * 0.22,
                page_width * 0.11,
                page_width * 0.22,
                page_width * 0.33,
            ],
        )
        table.setStyle(self._table_style("#065f46"))
        return [
            Paragraph("Remediation Actions This Run", styles["Heading2"]),
            table,
            Spacer(1, 10),
        ]

    def _findings_section(self, findings_list, page_width, cell, styles) -> List[object]:
        elements: List[object] = [Paragraph("Failed Findings", styles["Heading2"])]
        if not findings_list:
            elements.append(
                Paragraph("No failed findings were returned by this scan.", styles["Normal"])
            )
            return elements

        rows = [
            [
                self._cell(header, cell)
                for header in ("Service", "Region", "CIS Control", "Severity", "Resource", "Title")
            ]
        ]
        for finding in _sort_by_severity(findings_list):
            rows.append(
                [
                    self._cell(finding.get("service", "unknown"), cell),
                    self._cell(finding.get("region", "global"), cell),
                    self._cell(finding.get("cis_control", "N/A"), cell),
                    self._cell(finding.get("severity", "Unknown"), cell),
                    self._cell(finding.get("resource_id", "Unknown"), cell),
                    self._cell(finding.get("title", "Finding"), cell),
                ]
            )

        table = Table(
            rows,
            repeatRows=1,
            colWidths=[
                page_width * 0.10,
                page_width * 0.11,
                page_width * 0.11,
                page_width * 0.10,
                page_width * 0.24,
                page_width * 0.34,
            ],
        )
        table.setStyle(self._table_style("#0f172a"))
        elements.append(table)
        return elements

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _table_style(header_color: str) -> TableStyle:
        return TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_color)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),
            ]
        )

    @staticmethod
    def _collapse_passes(service_checks: List[dict]) -> tuple[List[dict], Dict[str, int]]:
        """Keep every non-PASS row; cap PASS rows per check id."""

        shown: List[dict] = []
        pass_seen: Counter = Counter()
        collapsed: Dict[str, int] = defaultdict(int)

        for check in service_checks:
            if _display_status(check) != "PASS":
                shown.append(check)
                continue
            check_id = str(check.get("check_id", "unknown"))
            pass_seen[check_id] += 1
            if pass_seen[check_id] <= MAX_PASS_ROWS_PER_CHECK:
                shown.append(check)
            else:
                collapsed[check_id] += 1

        return shown, dict(collapsed)

    @staticmethod
    def _cell(value: object, style: ParagraphStyle) -> Paragraph:
        return Paragraph(escape(str(value)), style)

    @staticmethod
    def _status_cell(check: dict, style: ParagraphStyle) -> Paragraph:
        status = _display_status(check)
        color = STATUS_COLORS.get(status, "#1f2937")
        return Paragraph(f'<font color="{color}"><b>{escape(status)}</b></font>', style)

    @staticmethod
    def _calculate_risk_score(checks: List[dict]) -> int:
        return calculate_risk_score(checks)

    @staticmethod
    def _service_status_chart(checks: List[dict], page_width: float) -> Drawing:
        services = ["iam", "ec2", "s3"]
        pass_counts: List[int] = []
        fail_counts: List[int] = []

        for service in services:
            service_checks = [
                check for check in checks if str(check.get("service", "")).lower() == service
            ]
            statuses = [_display_status(check) for check in service_checks]
            pass_counts.append(statuses.count("PASS"))
            fail_counts.append(statuses.count("FAIL"))

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


def calculate_risk_score(checks: List[dict]) -> int:
    """Score 0-100 from the check outcomes. Suppressed results do not count."""

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
        # Accepted risk is accepted: it is reported, but it does not score.
        if check.get("suppressed"):
            continue

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

        # First occurrence uses full weight; repeats are discounted and capped
        # so one bad control across 500 resources cannot zero the score alone.
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


# ----------------------------------------------------------------------
# Module helpers
# ----------------------------------------------------------------------


def _as_dict(item: object) -> dict:
    if isinstance(item, dict):
        return item
    if hasattr(item, "to_dict"):
        return item.to_dict()  # type: ignore[attr-defined]
    return asdict(item)  # type: ignore[arg-type]


def _display_status(check: dict) -> str:
    if check.get("suppressed"):
        return "SUPPRESSED"
    return str(check.get("status", "UNKNOWN")).upper()


def _detail_text(check: dict) -> str:
    message = str(check.get("message", ""))
    if check.get("suppressed"):
        return f"{message} [accepted risk: {check.get('suppression_reason', '')}]"
    return message


def _sort_by_severity(findings: List[dict]) -> List[dict]:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
    return sorted(
        findings,
        key=lambda f: (
            order.get(str(f.get("severity", "")).upper(), 5),
            str(f.get("service", "")),
            str(f.get("resource_id", "")),
        ),
    )
