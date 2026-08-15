"""CloudShield entrypoint.

Scanning is read-only. Nothing is changed in the target account unless you pass
both ``--remediate`` (execute rather than plan) and ``--allow`` (which check ids
you are authorising).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

from core.auth import AWSAuthManager, resolve_regions
from core.models import (
    STATUS_FAIL,
    CheckResult,
    Finding,
    error_check,
    severity_rank,
)
from core.suppressions import SuppressionError, apply_suppressions, load_suppressions
from remediators import registry
from reporters.pdf_reporter import PDFReporter, calculate_risk_score
from scanners.ec2_scanner import EC2Scanner
from scanners.iam_scanner import IAMScanner
from scanners.s3_scanner import S3Scanner

EXIT_OK = 0
EXIT_THRESHOLD_BREACHED = 1
EXIT_ERROR = 2

SEVERITY_CHOICES = ["none", "low", "medium", "high", "critical"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudshield",
        description="Scan an AWS account against CIS AWS Foundations controls.",
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        metavar="REGION",
        help="Regions to scan for regional services. Use 'all' for every enabled "
        "region. Defaults to the session region.",
    )
    parser.add_argument(
        "--report",
        default=os.getenv("CLOUDSHIELD_REPORT_PATH", "cloudshield_report.pdf"),
        help="Path for the PDF report.",
    )
    parser.add_argument(
        "--results",
        default=os.getenv("CLOUDSHIELD_RESULTS_PATH", "cloudshield_results.json"),
        help="Path for the JSON results.",
    )
    parser.add_argument(
        "--suppressions",
        help="Path to a suppression file. Defaults to cloudshield-suppressions.{yaml,yml,json} "
        "in the working directory if present.",
    )
    parser.add_argument(
        "--remediate",
        action="store_true",
        help="Apply remediations for allowed checks. Without this, remediations "
        "are only planned and printed.",
    )
    parser.add_argument(
        "--allow",
        nargs="+",
        default=[],
        metavar="CHECK_ID",
        help="Check ids that --remediate is permitted to act on, or 'all'.",
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITY_CHOICES,
        default="none",
        help="Exit non-zero if any unsuppressed check fails at or above this "
        "severity. Default: none.",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=None,
        metavar="N",
        help="Exit non-zero if the risk score is below N.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print the summary lines.",
    )
    return parser


# ----------------------------------------------------------------------
# Scanning
# ----------------------------------------------------------------------


def build_scanners(session, regions: Sequence[str]) -> List[Tuple[str, object]]:
    """IAM and S3 are global; EC2 is scanned once per region."""

    scanners: List[Tuple[str, object]] = [
        ("iam", IAMScanner(session)),
        ("s3", S3Scanner(session)),
    ]
    for region in regions:
        scanners.append((f"ec2/{region}", EC2Scanner(session, region=region)))
    return scanners


def run_scans(session, regions: Sequence[str], quiet: bool = False):
    findings: List[Finding] = []
    checks: List[CheckResult] = []

    try:
        scanners = build_scanners(session, regions)
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Unable to create AWS clients: {exc}") from exc

    max_workers = min(len(scanners), 12)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                scanner.scan_detailed
                if hasattr(scanner, "scan_detailed")
                else scanner.scan
            ): label
            for label, scanner in scanners
        }
        for future in as_completed(future_map):
            label = future_map[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - one scanner must not kill the run
                service, _, region = label.partition("/")
                checks.append(
                    error_check(
                        service=service,
                        resource_id=label,
                        resource_type="scanner",
                        check_id=f"{service.upper()}-SCANNER",
                        check_name=f"{service.upper()} scanner completed",
                        message=f"Scanner {label} failed and was skipped.",
                        error=exc,
                        region=region or "global",
                    )
                )
                if not quiet:
                    print(f"  ! {label}: {type(exc).__name__}: {exc}", file=sys.stderr)
                continue

            if isinstance(result, tuple):
                scanner_findings, scanner_checks = result
                findings.extend(scanner_findings)
                checks.extend(scanner_checks)
            else:
                findings.extend(result)
            if not quiet:
                print(f"  - {label} complete")

    return findings, checks


def get_scan_metadata(session, regions: Sequence[str], mode: str) -> Dict[str, str]:
    metadata: Dict[str, str] = {
        "region": session.region_name or os.getenv("AWS_REGION") or "unknown",
        "regions": ", ".join(regions),
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
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
            {"account_id": "unknown", "caller_arn": "unknown", "caller_user_id": "unknown"}
        )

    return metadata


# ----------------------------------------------------------------------
# Gating
# ----------------------------------------------------------------------


def gate(
    checks: Sequence[CheckResult], risk_score: int, fail_on: str, min_score: int | None
) -> Tuple[int, List[str]]:
    reasons: List[str] = []

    if fail_on != "none":
        threshold = severity_rank(fail_on)
        breaching = [
            check
            for check in checks
            if check.status == STATUS_FAIL
            and not check.suppressed
            and severity_rank(check.severity) >= threshold
        ]
        if breaching:
            counts: Dict[str, int] = {}
            for check in breaching:
                counts[check.severity] = counts.get(check.severity, 0) + 1
            summary = ", ".join(f"{count} {sev}" for sev, count in sorted(counts.items()))
            reasons.append(f"{len(breaching)} failing check(s) at or above {fail_on} ({summary})")

    if min_score is not None and risk_score < min_score:
        reasons.append(f"risk score {risk_score} is below the minimum of {min_score}")

    return (EXIT_THRESHOLD_BREACHED if reasons else EXIT_OK), reasons


# ----------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)

    try:
        suppressions = load_suppressions(args.suppressions)
    except SuppressionError as exc:
        print(f"Suppression file error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        session = AWSAuthManager().get_session()
        regions = resolve_regions(session, args.regions)
    except (RuntimeError, BotoCoreError, ClientError) as exc:
        print(f"AWS authentication failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    mode = "remediate" if args.remediate else "read-only scan"
    if not args.quiet:
        print(f"CloudShield: scanning {len(regions)} region(s): {', '.join(regions)}")

    scan_metadata = get_scan_metadata(session, regions, mode)

    try:
        findings, checks = run_scans(session, regions, quiet=args.quiet)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR

    checks, expired = apply_suppressions(checks, suppressions)
    for suppression in expired:
        print(
            f"Warning: suppression for {suppression.check_id} expired on "
            f"{suppression.expires.isoformat()} and was not applied.",
            file=sys.stderr,
        )

    suppressed_keys = {
        (check.check_id, check.resource_id) for check in checks if check.suppressed
    }
    findings = [
        finding
        for finding in findings
        if (finding.check_id, finding.resource_id) not in suppressed_keys
    ]

    remediation_results = registry.run(
        session, checks, allow=args.allow, apply_changes=args.remediate
    )
    remediation_payload = [result.to_dict() for result in remediation_results]

    for output_path in (args.report, args.results):
        parent = Path(output_path).expanduser().parent
        if str(parent):
            parent.mkdir(parents=True, exist_ok=True)

    reporter = PDFReporter(args.report)
    report_file = reporter.generate(
        findings, checks, scan_metadata, remediations=remediation_payload
    )
    risk_score = calculate_risk_score([check.to_dict() for check in checks])

    results_payload = {
        "scan_metadata": {**scan_metadata, "risk_score": risk_score},
        "findings": [finding.to_dict() for finding in findings],
        "checks": [check.to_dict() for check in checks],
        "remediations": remediation_payload,
    }
    with open(args.results, "w", encoding="utf-8") as results_file:
        json.dump(results_payload, results_file, indent=2, default=str)

    exit_code, reasons = gate(checks, risk_score, args.fail_on, args.min_score)

    failed = sum(1 for c in checks if c.status == STATUS_FAIL and not c.suppressed)
    errored = sum(1 for c in checks if c.status == "ERROR" and not c.suppressed)
    suppressed = sum(1 for c in checks if c.suppressed)

    print(
        f"\nScan complete: {len(checks)} checks | {failed} failed | "
        f"{errored} errored | {suppressed} suppressed"
    )
    print(f"Risk score: {risk_score}/100")
    print(f"Findings: {len(findings)}")

    applied = [r for r in remediation_results if r.status == registry.STATUS_APPLIED]
    planned = [r for r in remediation_results if r.status == registry.STATUS_PLANNED]
    skipped = [r for r in remediation_results if r.status == registry.STATUS_SKIPPED]
    failed_fixes = [r for r in remediation_results if r.status == registry.STATUS_FAILED]
    if remediation_results:
        print(
            f"Remediations: {len(applied)} applied | {len(planned)} planned | "
            f"{len(skipped)} not allowed | {len(failed_fixes)} failed"
        )
        if not args.quiet:
            for result in remediation_results:
                print(f"  [{result.status}] {result.check_id} {result.resource_id}: {result.message}")

    print(f"PDF report: {report_file}")
    print(f"JSON results: {args.results}")

    for reason in reasons:
        print(f"GATE FAILED: {reason}", file=sys.stderr)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
