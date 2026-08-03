"""OCI IAM collector.

Pulls users, groups, dynamic-groups, policies, and group memberships from the
OCI Identity service, returning the snapshot dict the OCI engine consumes.

Also collects the optional identity-lifecycle enrichment the inventory builder
understands (see ``cloudsplaining/identity_inventory/oci.py``):

- ``auditEvents`` — CreateUser / CreateDynamicGroup events from the OCI Audit
  service (needs ``Allow group <X> to read audit-events in tenancy``), which
  power ``created_by``. Fails open: without the permission the key is emitted
  as an empty list and ``created_by`` stays null.

Requires ``pip install 'cloudsplaining[oci]'`` (oci). Authentication uses the
standard OCI config file (``~/.oci/config``) / instance principals.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from cloudsplaining.identity_inventory.oci import CREATION_EVENT_SUFFIXES
from cloudsplaining.multicloud.collectors.base import Collector

logger = logging.getLogger(__name__)

#: OCI Audit retains 365 days but rejects startTime older than that *at request
#: time* — validated again on every paginated call — so stay a day inside it.
_AUDIT_LOOKBACK_DAYS = 364
#: Observed skew between a creation event's time and the resource's
#: timeCreated is ~0.1s; quick delete-recreate cycles put a namesake's event
#: ~90s off. Wider padding just adds pages of unrelated tenancy noise.
_AUDIT_WINDOW_PADDING = timedelta(minutes=2)
#: list_events has no server-side event-type filter, so a window that
#: coincides with heavy API traffic pages pure noise; cap it so one noisy
#: window cannot starve the rest.
_AUDIT_WINDOW_PAGE_LIMIT = 5
#: Global page budget across all windows: bounds collect() wall time on
#: tenancies with many distinct creation days.
_AUDIT_PAGE_LIMIT = 100


class OciCollector(Collector):
    name = "oci"
    extra = "oci"

    def __init__(
        self,
        tenancy_id: str | None = None,
        config_profile: str = "DEFAULT",
        config_file: str | None = None,
        client: Any | None = None,
        audit_client: Any | None = None,
        **_: Any,
    ) -> None:
        self._tenancy_id = tenancy_id
        self._config_profile = config_profile
        self._config_file = config_file
        self._client = client
        self._audit_client = audit_client

    def _config(self, oci: Any) -> dict[str, Any]:
        kwargs: dict[str, str] = {"profile_name": self._config_profile}
        if self._config_file:
            kwargs["file_location"] = self._config_file
        return oci.config.from_file(**kwargs)

    def client(self) -> tuple[Any, str]:
        """Return (IdentityClient, tenancy_ocid)."""
        if self._client is not None:
            return self._client, (self._tenancy_id or "")
        oci = self._import("oci")
        config = self._config(oci)
        tenancy = self._tenancy_id or config["tenancy"]
        return oci.identity.IdentityClient(config), tenancy

    def collect(self) -> dict[str, Any]:
        client, tenancy = self.client()
        users = self._list(client.list_users, tenancy)
        groups = self._list(client.list_groups, tenancy)
        dynamic_groups = self._list(client.list_dynamic_groups, tenancy)
        policies = self._policies(client, tenancy)
        memberships = self._memberships(client, tenancy, users, groups)

        return {
            "users": [self._user(u) for u in users],
            "groups": [self._named(g) for g in groups],
            "dynamicGroups": [self._dynamic_group(d) for d in dynamic_groups],
            "policies": policies,
            "groupMemberships": memberships,
            "auditEvents": self._audit_events(
                tenancy, [getattr(obj, "time_created", None) for obj in users + dynamic_groups]
            ),
        }

    # ------------------------------------------------------------- lifecycle
    def _audit_events(self, tenancy: str, creation_times: list[Any]) -> list[dict[str, Any]]:
        """Identity-creation audit events; they power created_by in the identity inventory.

        Queries short windows around each identity's timeCreated (where its
        creation event lives) rather than scanning the whole retention window,
        which takes minutes on active tenancies.
        """
        try:
            client = self._audit_client_or_none()
            if client is None:
                return []
            events: list[dict[str, Any]] = []
            budget = _AUDIT_PAGE_LIMIT
            for start_time, end_time in self._creation_windows(creation_times):
                page = None
                window_pages = 0
                while budget > 0 and window_pages < _AUDIT_WINDOW_PAGE_LIMIT:
                    budget -= 1
                    window_pages += 1
                    kwargs: dict[str, Any] = {"compartment_id": tenancy, "start_time": start_time, "end_time": end_time}
                    if page:
                        kwargs["page"] = page
                    resp = client.list_events(**kwargs)
                    events.extend(event for event in map(self._creation_event, resp.data) if event is not None)
                    page = resp.next_page
                    if not page:
                        break
                if budget <= 0:
                    break
            return events
        except Exception as error:
            logger.warning("Skipping auditEvents (created_by will be null): %s", error)
            return []

    def _audit_client_or_none(self) -> Any | None:
        if self._audit_client is not None:
            return self._audit_client
        if self._client is not None:
            # Injected-identity-client mode has no OCI config to build a real client from.
            return None
        oci = self._import("oci")
        return oci.audit.AuditClient(self._config(oci))

    @staticmethod
    def _creation_windows(creation_times: list[Any]) -> list[tuple[datetime, datetime]]:
        """Merged, padded query windows around identity creation times, clamped to retention.

        Newest first: if the page budget runs out, the identities most likely
        to still have their creation event in retention are covered first, and
        the inventory builder keeps the first event it sees per resource name.
        """
        now = datetime.now(timezone.utc)
        floor = now - timedelta(days=_AUDIT_LOOKBACK_DAYS)
        times = []
        for value in creation_times:
            if not isinstance(value, datetime):
                continue
            aware = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
            if aware >= floor:
                times.append(aware)
        windows: list[tuple[datetime, datetime]] = []
        for time in sorted(times):
            start = max(time - _AUDIT_WINDOW_PADDING, floor)
            end = min(time + _AUDIT_WINDOW_PADDING, now)
            if windows and start <= windows[-1][1]:
                windows[-1] = (windows[-1][0], max(end, windows[-1][1]))
            else:
                windows.append((start, end))
        return list(reversed(windows))

    @staticmethod
    def _creation_event(obj: Any) -> dict[str, Any] | None:
        event_type = str(getattr(obj, "event_type", None) or "")
        if not event_type.lower().endswith(CREATION_EVENT_SUFFIXES):
            return None
        data = getattr(obj, "data", None)
        identity = getattr(data, "identity", None)
        return {
            "eventType": event_type,
            "eventTime": getattr(obj, "event_time", None),
            "data": {
                "resourceName": getattr(data, "resource_name", None),
                "identity": {"principalName": getattr(identity, "principal_name", None)},
            },
        }

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _list(fn: Any, compartment_id: str) -> list[Any]:
        # OCI list_* calls are paginated; oci.pagination.list_call_get_all_results
        # is the idiomatic helper, but we page manually to avoid importing it.
        items: list[Any] = []
        page = None
        while True:
            resp = fn(compartment_id, page=page) if page else fn(compartment_id)
            items.extend(resp.data)
            page = resp.next_page
            if not page:
                break
        return items

    def _policies(self, client: Any, tenancy: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        # Policies can live in any compartment; collect the tenancy plus its
        # immediate compartments. Callers needing the full tree can pre-build a
        # snapshot; this covers the common flat layout.
        compartments = [tenancy] + [c.id for c in self._list(client.list_compartments, tenancy)]
        for compartment_id in compartments:
            for policy in self._list(client.list_policies, compartment_id):
                out.append(
                    {
                        "id": policy.id,
                        "name": policy.name,
                        "compartmentId": policy.compartment_id,
                        "statements": list(policy.statements or []),
                    }
                )
        return out

    def _memberships(self, client: Any, tenancy: str, users: list[Any], groups: list[Any]) -> dict[str, list[str]]:
        user_name = {u.id: u.name for u in users}
        memberships: dict[str, list[str]] = {}
        for group in groups:
            links = self._list_memberships(client, tenancy, group.id)
            names = [user_name.get(link.user_id) for link in links]
            memberships[group.name] = [n for n in names if n]
        return memberships

    def _list_memberships(self, client: Any, tenancy: str, group_id: str) -> list[Any]:
        items: list[Any] = []
        page = None
        while True:
            kwargs = {"compartment_id": tenancy, "group_id": group_id}
            if page:
                kwargs["page"] = page
            resp = client.list_user_group_memberships(**kwargs)
            items.extend(resp.data)
            page = resp.next_page
            if not page:
                break
        return items

    @staticmethod
    def _named(obj: Any) -> dict[str, Any]:
        return {"id": obj.id, "name": obj.name, "description": getattr(obj, "description", None)}

    @staticmethod
    def _user(obj: Any) -> dict[str, Any]:
        # ListUsers already returns the lifecycle/classification fields the
        # identity inventory consumes — no extra API calls needed.
        capabilities = getattr(obj, "capabilities", None)
        return {
            "id": obj.id,
            "name": obj.name,
            "description": getattr(obj, "description", None),
            "email": getattr(obj, "email", None),
            "timeCreated": getattr(obj, "time_created", None),
            "lastSuccessfulLoginTime": getattr(obj, "last_successful_login_time", None),
            "isMfaActivated": getattr(obj, "is_mfa_activated", None),
            "capabilities": (
                {
                    "canUseConsolePassword": getattr(capabilities, "can_use_console_password", None),
                    "canUseApiKeys": getattr(capabilities, "can_use_api_keys", None),
                }
                if capabilities is not None
                else None
            ),
        }

    @staticmethod
    def _dynamic_group(obj: Any) -> dict[str, Any]:
        return {
            "id": obj.id,
            "name": obj.name,
            "matching-rule": getattr(obj, "matching_rule", None),
            "timeCreated": getattr(obj, "time_created", None),
        }
