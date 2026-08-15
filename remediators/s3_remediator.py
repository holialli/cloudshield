"""S3 remediation helpers for CloudShield.

Kept as a thin, direct API for callers that want to fix a single bucket. The
scan pipeline goes through :mod:`remediators.registry` instead, which handles
allow-listing, dry runs and per-action error isolation.

Note the contract change: this no longer raises on API failure. The previous
version propagated a ``RuntimeError`` all the way out of ``main()``, which
destroyed the whole scan -- report included -- because one bucket could not be
written to.
"""

from __future__ import annotations

from typing import Dict, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from core.awsutil import BOTO_CONFIG

PUBLIC_ACCESS_BLOCK_CONFIG = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


class S3Remediator:
    """Apply S3 remediation actions."""

    def __init__(self, session: boto3.Session) -> None:
        self.session = session
        self.s3 = session.client("s3", config=BOTO_CONFIG)

    def enable_public_access_block(
        self, bucket_name: str, region: Optional[str] = None
    ) -> Dict[str, str]:
        """Enable all S3 Public Access Block settings for a bucket."""

        client = (
            self.session.client("s3", region_name=region, config=BOTO_CONFIG)
            if region and region != "global"
            else self.s3
        )

        try:
            client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration=PUBLIC_ACCESS_BLOCK_CONFIG,
            )
        except (BotoCoreError, ClientError) as exc:
            return {
                "bucket": bucket_name,
                "status": "failed",
                "action": "put_public_access_block",
                "error": str(exc),
            }

        return {
            "bucket": bucket_name,
            "status": "enabled",
            "action": "put_public_access_block",
        }
