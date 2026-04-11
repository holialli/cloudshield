"""CloudShield entrypoint."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List
from datetime import datetime, timezone

from botocore.exceptions import BotoCoreError, ClientError

from core.auth import AWSAuthManager
from remediators.s3_remediator import S3Remediator
from reporters.pdf_reporter import PDFReporter
from scanners.ec2_scanner import EC2Scanner
from scanners.iam_scanner import CheckResult, Finding, IAMScanner
from scanners.s3_scanner import S3Scanner
from dotenv import load_dotenv


def run_scans(session) -> tuple[List[Finding], List[CheckResult]]:
    scanners = [
        IAMScanner(session),
        S3Scanner(session),
        EC2Scanner(session),
    ]

    findings: List[Finding] = []
    checks: List[CheckResult] = []
    with ThreadPoolExecutor(max_workers=len(scanners)) as executor:
        future_map = {
            executor.submit(
                scanner.scan_detailed if hasattr(scanner, "scan_detailed") else scanner.scan
            ): scanner
            for scanner in scanners
        }
        for future in as_completed(future_map):
            result = future.result()
            if isinstance(result, tuple):
                scanner_findings, scanner_checks = result
                findings.extend(scanner_findings)
                checks.extend(scanner_checks)
            else:
                findings.extend(result)
    return findings, checks


def get_scan_metadata(session) -> Dict[str, str]:
    metadata: Dict[str, str] = {
        "region": session.region_name or os.getenv("AWS_REGION") or "unknown",
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    try:
        identity = session.client("sts").get_caller_identity()
        metadata.update(
            {
                "account_id": identity.get("Account", "unknown"),
                "caller_arn": identity.get("Arn", "unknown"),
                "caller_user_id": identity.get("UserId", "unknown"),
            }
        )
    except (BotoCoreError, ClientError):
        metadata.update(
            {
                "account_id": "unknown",
                "caller_arn": "unknown",
                "caller_user_id": "unknown",
            }
        )

    return metadata


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
    scan_metadata = get_scan_metadata(session)

    findings, checks = run_scans(session)
    remediation_results = remediate_high_severity_s3(session, findings)

    output_path = os.getenv("CLOUDSHIELD_REPORT_PATH", "cloudshield_report.pdf")
    reporter = PDFReporter(output_path)
    report_file = reporter.generate(findings, checks, scan_metadata)

    results_path = os.getenv("CLOUDSHIELD_RESULTS_PATH", "cloudshield_results.json")
    results_payload = {
        "scan_metadata": scan_metadata,
        "findings": [finding.to_dict() for finding in findings],
        "checks": [check.to_dict() for check in checks],
        "remediations": remediation_results,
    }
    with open(results_path, "w", encoding="utf-8") as results_file:
        json.dump(results_payload, results_file, indent=2)

    print(f"Scans completed: {len(findings)} findings")
    print(f"Remediations applied: {len(remediation_results)}")
    print(f"PDF report generated: {report_file}")
    print(f"JSON results generated: {results_path}")


if __name__ == "__main__":
    main()
