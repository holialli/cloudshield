"""Shared result models for CloudShield scanners.

Scanners emit two parallel records:

* ``CheckResult`` -- one per control evaluated, whatever the outcome. This is the
  complete audit trail and drives the risk score, the report tables and the
  remediation engine.
* ``Finding`` -- emitted only for controls that actually failed. Drives the
  "Failed Findings" summary and the remediation targets.

API errors produce an ``ERROR`` ``CheckResult`` only. They are not findings:
"we could not evaluate this" is not the same claim as "this is misconfigured",
and mixing the two made the findings table unreadable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

GLOBAL_REGION = "global"

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_ERROR = "ERROR"
STATUS_EXCEPTION = "EXCEPTION"
STATUS_INFO = "INFO"

#: Severity ordering, low to high. Used by the CI gate and the risk score.
SEVERITY_ORDER: List[str] = ["Informational", "Low", "Medium", "High", "Critical"]


def severity_rank(severity: str) -> int:
    """Return a comparable rank for a severity label (unknown -> Low)."""

    try:
        return SEVERITY_ORDER.index(str(severity).capitalize())
    except ValueError:
        return SEVERITY_ORDER.index("Low")


@dataclass
class Finding:
    service: str
    resource_id: str
    title: str
    description: str
    severity: str
    cis_control: str
    remediation: str
    details: Dict[str, Any]
    region: str = GLOBAL_REGION
    check_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CheckResult:
    service: str
    resource_id: str
    resource_type: str
    check_id: str
    check_name: str
    status: str
    severity: str
    cis_control: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    region: str = GLOBAL_REGION
    suppressed: bool = False
    suppression_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def counts_against_score(self) -> bool:
        """Whether this result should penalise the risk score / fail the gate."""

        return not self.suppressed and self.status in {STATUS_FAIL, STATUS_ERROR}


def error_check(
    *,
    service: str,
    resource_id: str,
    resource_type: str,
    check_id: str,
    check_name: str,
    message: str,
    error: Exception | str,
    severity: str = "Medium",
    cis_control: str = "N/A",
    region: str = GLOBAL_REGION,
    details: Dict[str, Any] | None = None,
) -> CheckResult:
    """Build an ``ERROR`` result for an AWS call that could not be evaluated."""

    payload: Dict[str, Any] = {"error": str(error)}
    if details:
        payload.update(details)
    return CheckResult(
        service=service,
        resource_id=resource_id,
        resource_type=resource_type,
        check_id=check_id,
        check_name=check_name,
        status=STATUS_ERROR,
        severity=severity,
        cis_control=cis_control,
        message=message,
        details=payload,
        region=region,
    )
