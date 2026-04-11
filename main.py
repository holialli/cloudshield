"""CloudShield entrypoint."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from core.auth import AWSAuthManager
from remediators.s3_remediator import S3Remediator
from reporters.pdf_reporter import PDFReporter
from scanners.ec2_scanner import EC2Scanner
from scanners.iam_scanner import Finding, IAMScanner
from scanners.s3_scanner import S3Scanner
from dotenv import load_dotenv


def run_scans(session) -> List[Finding]:
    scanners = [
        IAMScanner(session),
        S3Scanner(session),
        EC2Scanner(session),
    ]

    findings: List[Finding] = []
    with ThreadPoolExecutor(max_workers=len(scanners)) as executor:
        future_map = {executor.submit(scanner.scan): scanner for scanner in scanners}
        for future in as_completed(future_map):
            findings.extend(future.result())
    return findings


def remediate_high_severity_s3(session, findings: List[Finding]) -> List[Dict[str, str]]:
    remediator = S3Remediator(session)
    results: List[Dict[str, str]] = []

    for finding in findings:
        if finding.service != "s3" or finding.severity != "High":
            continue
        bucket_name = finding.details.get("bucket") or finding.resource_id
        if not bucket_name:
            continue
        result = remediator.enable_public_access_block(bucket_name)
        results.append(result)

    return results


def main() -> None:
    load_dotenv()
    auth = AWSAuthManager()
    session = auth.get_session()

    findings = run_scans(session)
    remediation_results = remediate_high_severity_s3(session, findings)

    output_path = os.getenv("CLOUDSHIELD_REPORT_PATH", "cloudshield_report.pdf")
    reporter = PDFReporter(output_path)
    report_file = reporter.generate(findings)

    print(f"Scans completed: {len(findings)} findings")
    print(f"Remediations applied: {len(remediation_results)}")
    print(f"PDF report generated: {report_file}")


if __name__ == "__main__":
    main()
