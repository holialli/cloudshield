"""Accepted-risk suppressions for CloudShield.

A suppression marks a specific ``(check_id, resource_id)`` pair as accepted risk
so it stops penalising the risk score and stops failing the CI gate, without
hiding it from the report. Every suppression needs a justification and an
expiry date -- an accepted risk with no end date is just an ignored one.

File format (YAML or JSON, chosen by file extension)::

    suppressions:
      - check_id: EC2-NO-PUBLIC-IP
        resource_id: i-0abc123           # optional, "*" or omitted = all resources
        region: us-east-1                # optional, omitted = all regions
        reason: Public bastion, access restricted to the VPN CIDR.
        expires: 2026-12-31              # required, YYYY-MM-DD
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from core.models import CheckResult

DEFAULT_SUPPRESSION_FILES = (
    "cloudshield-suppressions.yaml",
    "cloudshield-suppressions.yml",
    "cloudshield-suppressions.json",
)


@dataclass(frozen=True)
class Suppression:
    check_id: str
    reason: str
    expires: date
    resource_id: str = "*"
    region: str = "*"

    def is_expired(self, today: Optional[date] = None) -> bool:
        return self.expires < (today or date.today())

    def matches(self, check: CheckResult) -> bool:
        if not fnmatch.fnmatch(check.check_id, self.check_id):
            return False
        if not fnmatch.fnmatch(check.resource_id, self.resource_id):
            return False
        return fnmatch.fnmatch(check.region, self.region)


class SuppressionError(ValueError):
    """Raised when a suppression file is malformed."""


def _load_raw(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)

    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - depends on install
        raise SuppressionError(
            f"{path} is YAML but PyYAML is not installed. "
            "Run 'pip install -r requirements.txt' or use a .json suppression file."
        ) from exc
    return yaml.safe_load(text) or {}


def _parse_expiry(value: object, check_id: str) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        try:
            return datetime.strptime(value.strip(), "%Y-%m-%d").date()
        except ValueError as exc:
            raise SuppressionError(
                f"Suppression for {check_id} has an invalid 'expires' value: {value!r} "
                "(expected YYYY-MM-DD)."
            ) from exc
    raise SuppressionError(f"Suppression for {check_id} is missing a required 'expires' date.")


def load_suppressions(path: Optional[str] = None) -> List[Suppression]:
    """Load suppressions from ``path``, or from the default file names."""

    candidates: Sequence[Path]
    if path:
        candidates = [Path(path)]
        if not candidates[0].exists():
            raise SuppressionError(f"Suppression file not found: {path}")
    else:
        candidates = [Path(name) for name in DEFAULT_SUPPRESSION_FILES]

    for candidate in candidates:
        if not candidate.exists():
            continue

        raw = _load_raw(candidate)
        entries = raw.get("suppressions", []) if isinstance(raw, dict) else raw
        if not isinstance(entries, list):
            raise SuppressionError(f"{candidate}: 'suppressions' must be a list.")

        suppressions: List[Suppression] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise SuppressionError(f"{candidate}: each suppression must be a mapping.")
            check_id = str(entry.get("check_id", "")).strip()
            if not check_id:
                raise SuppressionError(f"{candidate}: a suppression is missing 'check_id'.")
            reason = str(entry.get("reason", "")).strip()
            if not reason:
                raise SuppressionError(f"{candidate}: suppression {check_id} is missing 'reason'.")
            suppressions.append(
                Suppression(
                    check_id=check_id,
                    reason=reason,
                    expires=_parse_expiry(entry.get("expires"), check_id),
                    resource_id=str(entry.get("resource_id", "*") or "*"),
                    region=str(entry.get("region", "*") or "*"),
                )
            )
        return suppressions

    return []


def apply_suppressions(
    checks: Iterable[CheckResult],
    suppressions: Sequence[Suppression],
    today: Optional[date] = None,
) -> tuple[List[CheckResult], List[Suppression]]:
    """Mark matching FAIL/ERROR checks as suppressed.

    Returns the checks (mutated in place) and the list of expired suppressions,
    so the caller can warn about them rather than silently honouring stale
    exceptions.
    """

    check_list = list(checks)
    active = [s for s in suppressions if not s.is_expired(today)]
    expired = [s for s in suppressions if s.is_expired(today)]

    for check in check_list:
        if check.status not in {"FAIL", "ERROR"}:
            continue
        for suppression in active:
            if suppression.matches(check):
                check.suppressed = True
                check.suppression_reason = (
                    f"{suppression.reason} (expires {suppression.expires.isoformat()})"
                )
                break

    return check_list, expired
