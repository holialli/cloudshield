"""AWS authentication helpers for CloudShield."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from core.awsutil import BOTO_CONFIG


@dataclass(frozen=True)
class AWSAuthConfig:
    """Runtime configuration for AWS sessions."""

    region_name: Optional[str] = None
    role_arn: Optional[str] = None
    role_session_name: str = "CloudShieldSession"
    external_id: Optional[str] = None

    @classmethod
    def from_env(cls) -> "AWSAuthConfig":
        """Build a config from the environment variables the README documents."""

        return cls(
            region_name=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"),
            role_arn=os.getenv("AWS_ROLE_ARN") or None,
            role_session_name=os.getenv("AWS_ROLE_SESSION_NAME") or "CloudShieldSession",
            external_id=os.getenv("AWS_EXTERNAL_ID") or None,
        )


class AWSAuthManager:
    """Build boto3 sessions using instance profiles or STS assume-role."""

    def __init__(self, config: Optional[AWSAuthConfig] = None) -> None:
        self.config = config or AWSAuthConfig.from_env()

    def get_session(self) -> boto3.Session:
        """Return a boto3 Session for the current runtime context.

        When a role ARN is configured the returned session carries *refreshable*
        credentials. A multi-region scan of a large account can easily outlive
        the one-hour default assume-role lifetime, and static credentials would
        start failing partway through with no obvious cause.
        """

        base_session = boto3.Session(region_name=self.config.region_name)

        if not self.config.role_arn:
            return base_session

        try:
            return self._refreshable_role_session(base_session)
        except Exception:  # noqa: BLE001 - private botocore API, fall back if it moves
            return self._static_role_session(base_session)

    def _assume_role_kwargs(self) -> dict:
        kwargs: dict[str, Any] = {"RoleSessionName": self.config.role_session_name}
        if self.config.external_id:
            kwargs["ExternalId"] = self.config.external_id
        return kwargs

    def _refreshable_role_session(self, base_session: boto3.Session) -> boto3.Session:
        from botocore.credentials import (
            AssumeRoleCredentialFetcher,
            DeferredRefreshableCredentials,
        )
        from botocore.session import get_session as get_botocore_session

        fetcher = AssumeRoleCredentialFetcher(
            client_creator=base_session._session.create_client,  # noqa: SLF001
            source_credentials=base_session.get_credentials(),
            role_arn=self.config.role_arn,
            extra_args=self._assume_role_kwargs(),
        )
        botocore_session = get_botocore_session()
        botocore_session._credentials = DeferredRefreshableCredentials(  # noqa: SLF001
            method="assume-role",
            refresh_using=fetcher.fetch_credentials,
        )
        return boto3.Session(
            botocore_session=botocore_session,
            region_name=self.config.region_name,
        )

    def _static_role_session(self, base_session: boto3.Session) -> boto3.Session:
        sts_client = base_session.client("sts", config=BOTO_CONFIG)
        try:
            response = sts_client.assume_role(
                RoleArn=self.config.role_arn, **self._assume_role_kwargs()
            )
        except (BotoCoreError, ClientError) as exc:
            raise RuntimeError(f"Unable to assume AWS role {self.config.role_arn}") from exc

        credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=self.config.region_name,
        )


def resolve_regions(session: boto3.Session, requested: Optional[List[str]]) -> List[str]:
    """Resolve the list of regions to scan for regional services.

    ``requested`` may be ``None`` (use the session region), ``["all"]`` (every
    region enabled for the account), or an explicit list.
    """

    if requested and [r.lower() for r in requested] != ["all"]:
        return list(dict.fromkeys(requested))

    if not requested:
        region = session.region_name or os.getenv("AWS_REGION") or "us-east-1"
        return [region]

    # "all": prefer the regions actually enabled for this account, and fall back
    # to the static endpoint list if we cannot describe them.
    try:
        ec2 = session.client("ec2", config=BOTO_CONFIG)
        regions = [
            entry["RegionName"]
            for entry in ec2.describe_regions(AllRegions=False).get("Regions", [])
        ]
        if regions:
            return sorted(regions)
    except (BotoCoreError, ClientError):
        pass

    return sorted(session.get_available_regions("ec2"))
