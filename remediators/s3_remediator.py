"""S3 remediation helpers for CloudShield."""

from __future__ import annotations

from typing import Dict

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class S3Remediator:
    """Apply S3 remediation actions."""

    def __init__(self, session: boto3.Session) -> None:
        self.s3 = session.client("s3")

    def enable_public_access_block(self, bucket_name: str) -> Dict[str, str]:
        """Enable all S3 Public Access Block settings for a bucket."""

        config = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

        try:
            self.s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration=config,
            )
        except (BotoCoreError, ClientError) as exc:
            raise RuntimeError(
                f"Failed to enable S3 Public Access Block for {bucket_name}"
            ) from exc

        return {
            "bucket": bucket_name,
            "status": "enabled",
            "action": "put_public_access_block",
        }
