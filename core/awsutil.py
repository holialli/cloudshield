"""Small boto3/botocore helpers shared by the scanners."""

from __future__ import annotations

from typing import Any, Dict, Iterator, List

from botocore.config import Config
from botocore.exceptions import ClientError

#: Applied to every client we create. IAM in particular throttles aggressively
#: once the scanners start paginating, so adaptive retries are not optional.
BOTO_CONFIG = Config(
    retries={"mode": "adaptive", "max_attempts": 10},
    connect_timeout=10,
    read_timeout=60,
)


def error_code(exc: Exception) -> str:
    """Return the AWS error code for a ClientError, or '' for anything else."""

    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code", ""))
    return ""


def is_access_denied(exc: Exception) -> bool:
    return error_code(exc) in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthorizationError",
    }


def paginate(client: Any, operation: str, result_key: str, **kwargs: Any) -> Iterator[Dict]:
    """Yield every item under ``result_key`` across all pages of ``operation``.

    Falls back to a single unpaginated call for operations botocore does not
    model a paginator for.
    """

    if client.can_paginate(operation):
        for page in client.get_paginator(operation).paginate(**kwargs):
            for item in page.get(result_key, []) or []:
                yield item
        return

    response = getattr(client, operation)(**kwargs)
    for item in response.get(result_key, []) or []:
        yield item


def paginate_list(client: Any, operation: str, result_key: str, **kwargs: Any) -> List[Dict]:
    return list(paginate(client, operation, result_key, **kwargs))


def as_list(value: Any) -> List[Any]:
    """Normalise an IAM policy field that may be a scalar, list, or absent."""

    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
