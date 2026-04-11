"""AWS authentication helpers for CloudShield."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError


@dataclass(frozen=True)
class AWSAuthConfig:
    """Runtime configuration for AWS sessions."""

    region_name: Optional[str] = None
    role_arn: Optional[str] = None
    role_session_name: str = "CloudShieldSession"
    external_id: Optional[str] = None


class AWSAuthManager:
    """Build boto3 sessions using instance profiles or STS assume-role."""

    def __init__(self, config: Optional[AWSAuthConfig] = None) -> None:
        self.config = config or AWSAuthConfig(
            region_name=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        )

    def get_session(self) -> boto3.Session:
        """Return a boto3 Session for the current runtime context."""

        base_session = boto3.Session(region_name=self.config.region_name)

        if not self.config.role_arn:
            return base_session

        sts_client = base_session.client("sts")
        assume_role_params: dict[str, Any] = {
            "RoleArn": self.config.role_arn,
            "RoleSessionName": self.config.role_session_name,
        }

        if self.config.external_id:
            assume_role_params["ExternalId"] = self.config.external_id

        try:
            response = sts_client.assume_role(**assume_role_params)
        except (BotoCoreError, ClientError) as exc:
            raise RuntimeError("Unable to assume AWS role") from exc

        credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=self.config.region_name,
        )
