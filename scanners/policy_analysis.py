"""IAM policy document analysis.

The original implementation matched only the exact string ``"*"``, which both
over- and under-reported:

* ``{"Effect": "Deny", "Action": "*"}`` is a guardrail, not a privilege, and was
  being flagged as a High finding.
* ``"s3:*"``, ``"iam:*"`` and ``NotAction`` grants are the common real-world
  shape of over-permission and were all reported as clean.

This module evaluates ``Allow`` statements only and grades what it finds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from core.awsutil import as_list
from core.models import severity_rank

FULL_ADMIN = "full-admin"
SERVICE_WILDCARD = "service-wildcard"
RESOURCE_WILDCARD = "resource-wildcard"
NOT_ACTION = "not-action"


@dataclass(frozen=True)
class PolicyIssue:
    kind: str
    severity: str
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {"kind": self.kind, "severity": self.severity, "detail": self.detail}


def analyse_policy_document(document: Any) -> List[PolicyIssue]:
    """Return the over-permission issues in an IAM policy document."""

    if not isinstance(document, dict):
        return []

    issues: List[PolicyIssue] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, severity: str, detail: str) -> None:
        key = (kind, detail)
        if key not in seen:
            seen.add(key)
            issues.append(PolicyIssue(kind=kind, severity=severity, detail=detail))

    for statement in as_list(document.get("Statement")):
        if not isinstance(statement, dict):
            continue
        # Deny statements restrict access; they are never an over-permission.
        if str(statement.get("Effect", "Allow")) != "Allow":
            continue

        actions = [str(a) for a in as_list(statement.get("Action"))]
        not_actions = [str(a) for a in as_list(statement.get("NotAction"))]
        resources = [str(r) for r in as_list(statement.get("Resource"))]
        # A condition can scope an otherwise-broad grant (e.g. aws:PrincipalOrgID),
        # so we still report it but one severity band lower.
        conditioned = bool(statement.get("Condition"))

        action_star = any(action == "*" for action in actions)
        resource_star = any(resource == "*" for resource in resources)

        if action_star and resource_star:
            add(
                FULL_ADMIN,
                "Medium" if conditioned else "High",
                "Allow Action:* on Resource:*"
                + (" (scoped by a Condition)" if conditioned else ""),
            )
        else:
            if action_star:
                add(SERVICE_WILDCARD, "Medium", "Allow Action:* on scoped resources")
            for action in actions:
                if action != "*" and action.endswith(":*"):
                    add(SERVICE_WILDCARD, "Medium", f"Allow {action}")
            if resource_star and actions:
                add(RESOURCE_WILDCARD, "Medium", "Allow on Resource:*")

        if not_actions:
            add(
                NOT_ACTION,
                "Medium",
                "Allow with NotAction: " + ", ".join(sorted(not_actions)[:5]),
            )

    return issues


def highest_severity(issues: List[PolicyIssue], default: str = "Informational") -> str:
    if not issues:
        return default
    return max((issue.severity for issue in issues), key=severity_rank)


def summarise(issues: List[PolicyIssue], limit: int = 4) -> str:
    details = [issue.detail for issue in issues]
    if len(details) <= limit:
        return "; ".join(details)
    return "; ".join(details[:limit]) + f"; +{len(details) - limit} more"
