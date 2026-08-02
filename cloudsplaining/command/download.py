"""Runs aws iam get-authorization-details on all accounts specified in the aws credentials file, and stores them in
account-alias.json"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import csv
import io
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import boto3
import click
from botocore.config import Config
from botocore.exceptions import ClientError

from cloudsplaining import set_log_level

if TYPE_CHECKING:
    from types_boto3_iam import IAMClient

logger = logging.getLogger(__name__)


@click.command(
    short_help="Runs aws iam get-authorization-details on all accounts specified in the aws credentials "
    "file, and stores them in account-alias.json"
)
@click.option(
    "-p",
    "--profile",
    type=str,
    required=False,
    envvar="AWS_DEFAULT_PROFILE",
    help="Specify 'all' to authenticate to AWS and scan from *all* AWS credentials profiles. Specify a non-default profile here. Defaults to the 'default' profile.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(exists=True),
    default=os.getcwd(),  # noqa: PTH109
    help="Path to store the output. Defaults to current directory.",
)
@click.option(
    "--include-non-default-policy-versions",
    is_flag=True,
    default=False,
    help="When downloading AWS managed policy documents, also include the non-default policy versions. Note that this will dramatically increase the size of the downloaded file.",
)
@click.option(
    "--skip-credential-report",
    is_flag=True,
    default=False,
    help="Don't fetch the IAM credential report. The report powers human/machine classification "
    "(console password, MFA, access-key state) and user last-used data in the identity inventory.",
)
@click.option(
    "--skip-cloudtrail-events",
    is_flag=True,
    default=False,
    help="Don't fetch CreateUser/CreateRole events from CloudTrail event history (last 90 days). "
    "They power created_by attribution in the identity inventory.",
)
@click.option("-v", "--verbose", "verbosity", help="Log verbosity level.", count=True)
def download(
    profile: str,
    output: str,
    include_non_default_policy_versions: bool,
    skip_credential_report: bool,
    skip_cloudtrail_events: bool,
    verbosity: int,
) -> int:
    """
    Runs aws iam get-authorization-details on all accounts specified in the aws credentials file, and stores them in
    account-alias.json
    """
    set_log_level(verbosity)

    default_region = "us-east-1"
    session_data = {"region_name": default_region}

    output_path = Path(output)
    if profile:
        session_data["profile_name"] = profile
        output_filename = output_path / f"{profile}.json"
    else:
        output_filename = output_path / "default.json"

    results: dict[str, Any] = get_account_authorization_details(session_data, include_non_default_policy_versions)
    if not skip_credential_report:
        report = get_credential_report(_iam_client(session_data))
        if report is not None:
            report_text, generated_time = report
            results["credentialReport"] = report_text
            if generated_time:
                results["credentialReportGeneratedTime"] = generated_time
            missing = users_missing_from_report(results.get("UserDetailList") or [], report_text)
            if missing:
                results["credentialSupplement"] = get_credential_supplement(_iam_client(session_data), missing)
    if not skip_cloudtrail_events:
        events = get_cloudtrail_create_events(_cloudtrail_client(session_data))
        if events is not None:
            results["cloudTrailEvents"] = events
    with output_filename.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, default=str)
    # output_filename.write_text(json.dumps(results, indent=4, default=str))
    print(f"Saved results to {output_filename}")
    return 1


def _iam_client(session_data: dict[str, str]) -> IAMClient:
    session = boto3.Session(**session_data)  # ty: ignore[invalid-argument-type]
    config = Config(connect_timeout=5, retries={"max_attempts": 10})
    return session.client("iam", config=config)


def _cloudtrail_client(session_data: dict[str, str]) -> Any:  # noqa: ANN401 - no type stubs for cloudtrail
    session = boto3.Session(**session_data)  # ty: ignore[invalid-argument-type]
    config = Config(connect_timeout=5, retries={"max_attempts": 10})
    return session.client("cloudtrail", config=config)


#: IAM identity- and credential-creation events for the identity inventory:
#: CreateUser/CreateRole resolve created_by; CreateAccessKey/CreateLoginProfile
#: classify users the cached credential report predates.
CLOUDTRAIL_CREATE_EVENT_NAMES = ("CreateUser", "CreateRole", "CreateAccessKey", "CreateLoginProfile")


def get_cloudtrail_create_events(
    cloudtrail_client: Any,  # noqa: ANN401 - no type stubs for cloudtrail
    event_names: tuple[str, ...] = CLOUDTRAIL_CREATE_EVENT_NAMES,
) -> list[dict[str, Any]] | None:
    """Fetch identity-creation events from CloudTrail event history.

    Powers ``created_by`` attribution in the identity inventory. The event-history
    API only reaches back 90 days, so only identities created inside that window
    are attributable this way. Returns ``None`` when the caller cannot look up
    events (e.g. missing cloudtrail:LookupEvents) so the download still succeeds.
    """
    events: list[dict[str, Any]] = []
    try:
        paginator = cloudtrail_client.get_paginator("lookup_events")
        for event_name in event_names:
            for page in paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}]
            ):
                events.extend(page.get("Events", []))
    except Exception as error:
        # Best-effort enrichment: never let it break the core download.
        logger.warning("Skipping CloudTrail creation events: %s", error)
        return None
    return events


def get_credential_report(
    iam_client: IAMClient, max_attempts: int = 30, delay_seconds: float = 2.0
) -> tuple[str, str | None] | None:
    """Generate and fetch the account's IAM credential report as ``(csv_text, generated_time)``.

    The report is the offline source for the identity inventory's credential-shape
    classification (password_enabled / mfa_active / access_key_*_active) and user
    last-used timestamps. AWS serves a cached report for up to four hours, so
    ``generated_time`` (ISO text, or ``None`` when the API omits it) lets consumers
    reason about users created after it. Returns ``None`` when the caller cannot
    generate it (e.g. missing iam:GenerateCredentialReport) so the download still
    succeeds.
    """
    try:
        for _ in range(max_attempts):
            if iam_client.generate_credential_report()["State"] == "COMPLETE":
                break
            time.sleep(delay_seconds)
        else:
            logger.warning("Credential report was not ready after %s attempts; skipping.", max_attempts)
            return None
        response = iam_client.get_credential_report()
        content = response["Content"]
    except ClientError as error:
        logger.warning("Skipping credential report: %s", error)
        return None
    generated = response.get("GeneratedTime")
    generated_text = generated.isoformat() if hasattr(generated, "isoformat") else generated
    text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
    return text, generated_text


#: Ceiling on per-user supplement lookups; the report gap is normally 0-2 users.
CREDENTIAL_SUPPLEMENT_CAP = 50


def users_missing_from_report(user_detail_list: list[dict[str, Any]], report_text: str) -> list[str]:
    """User names present in the authorization details but absent from the credential report."""
    reported = {row.get("user") for row in csv.DictReader(io.StringIO(report_text))}
    return [name for user in user_detail_list if (name := user.get("UserName")) and name not in reported]


def get_credential_supplement(iam_client: IAMClient, user_names: list[str]) -> dict[str, dict[str, Any]]:
    """Live credential shape for users the cached report predates.

    Best-effort per call: a denied call omits its keys, and classification treats a
    row missing either authoritative field as no evidence.
    """
    if len(user_names) > CREDENTIAL_SUPPLEMENT_CAP:
        logger.warning(
            "Credential supplement capped at %s of %s users missing from the report.",
            CREDENTIAL_SUPPLEMENT_CAP,
            len(user_names),
        )
        user_names = user_names[:CREDENTIAL_SUPPLEMENT_CAP]
    supplement: dict[str, dict[str, Any]] = {}
    for name in user_names:
        row: dict[str, Any] = {"checked_at": datetime.now(timezone.utc).isoformat()}
        try:
            keys = iam_client.list_access_keys(UserName=name)["AccessKeyMetadata"]
            row["access_keys_active"] = sum(1 for key in keys if key.get("Status") == "Active")
        except ClientError as error:
            logger.warning("Supplement list_access_keys(%s): %s", name, error)
        try:
            iam_client.get_login_profile(UserName=name)
            row["has_login_profile"] = True
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in ("NoSuchEntity", "NoSuchEntityException"):
                row["has_login_profile"] = False
            else:
                logger.warning("Supplement get_login_profile(%s): %s", name, error)
        try:
            row["mfa_devices"] = len(iam_client.list_mfa_devices(UserName=name)["MFADevices"])
        except ClientError as error:
            logger.warning("Supplement list_mfa_devices(%s): %s", name, error)
        supplement[name] = row
    return supplement


def get_account_authorization_details(
    session_data: dict[str, str], include_non_default_policy_versions: bool
) -> dict[str, list[Any]]:
    """Runs aws-iam-get-account-authorization-details"""
    iam_client = _iam_client(session_data)

    results: dict[str, list[Any]] = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    paginator = iam_client.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=["User"]):
        # Always add inline user policies
        results["UserDetailList"].extend(page["UserDetailList"])
    for page in paginator.paginate(Filter=["Group"]):
        results["GroupDetailList"].extend(page["GroupDetailList"])
    for page in paginator.paginate(Filter=["Role"]):
        results["RoleDetailList"].extend(page["RoleDetailList"])
        # Ignore Service Linked Roles
        for policy in page["Policies"]:
            if policy["Path"] != "/service-role/":
                results["RoleDetailList"].append(policy)
    for page in paginator.paginate(Filter=["LocalManagedPolicy"]):
        # Add customer-managed policies IF they are attached to IAM principals
        for policy in page["Policies"]:
            if policy["AttachmentCount"] > 0:
                results["Policies"].append(policy)
    for page in paginator.paginate(Filter=["AWSManagedPolicy"]):
        # Add customer-managed policies IF they are attached to IAM principals
        for policy in page["Policies"]:
            if policy["AttachmentCount"] > 0:
                if include_non_default_policy_versions:
                    results["Policies"].append(policy)
                else:
                    policy_version_list = []
                    for policy_version in policy.get("PolicyVersionList") or []:
                        if policy_version.get("VersionId") == policy.get("DefaultVersionId"):
                            policy_version_list.append(policy_version)
                            break
                    entry = {
                        "PolicyName": policy.get("PolicyName"),
                        "PolicyId": policy.get("PolicyId"),
                        "Arn": policy.get("Arn"),
                        "Path": policy.get("Path"),
                        "DefaultVersionId": policy.get("DefaultVersionId"),
                        "AttachmentCount": policy.get("AttachmentCount"),
                        "PermissionsBoundaryUsageCount": policy.get("PermissionsBoundaryUsageCount"),
                        "IsAttachable": policy.get("IsAttachable"),
                        "CreateDate": policy.get("CreateDate"),
                        "UpdateDate": policy.get("UpdateDate"),
                        "PolicyVersionList": policy_version_list,
                    }
                    results["Policies"].append(entry)
    return results
