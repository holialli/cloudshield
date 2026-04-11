"""PDF reporting for CloudShield."""

from __future__ import annotations

from dataclasses import asdict
from typing import Iterable, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
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

    def generate(self, findings: Iterable[object]) -> str:
        findings_list = [finding.to_dict() if hasattr(finding, "to_dict") else asdict(finding) for finding in findings]  # type: ignore[arg-type]
        risk_score = self._calculate_risk_score(findings_list)

        document = SimpleDocTemplate(self.output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        elements: List[object] = []

        elements.append(Paragraph("CloudShield Security Summary", styles["Title"]))
        elements.append(Spacer(1, 12))
        elements.append(
            Paragraph(f"Security Risk Score: <b>{risk_score}</b>/100", styles["Heading2"])
        )
        elements.append(Spacer(1, 12))

        summary_rows = [["CIS Control", "Severity", "Resource", "Title"]]
        for finding in findings_list:
            summary_rows.append(
                [
                    finding.get("cis_control", "N/A"),
                    finding.get("severity", "Unknown"),
                    finding.get("resource_id", "Unknown"),
                    finding.get("title", "Finding"),
                ]
            )

        table = Table(summary_rows, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        elements.append(table)
        document.build(elements)
        return self.output_path

    @staticmethod
    def _calculate_risk_score(findings: List[dict]) -> int:
        if not findings:
            return 100

        severity_weights = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3}
        score = 100
        for finding in findings:
            score -= severity_weights.get(finding.get("severity", "Low"), 3)
        return max(0, min(100, score))
