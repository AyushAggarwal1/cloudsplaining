"""OCI IAM collector.

Pulls users, groups, dynamic-groups, policies, and group memberships from the
OCI Identity service, returning the snapshot dict the OCI engine consumes.

Identities come from two places:

- The tenancy root, through the legacy Identity API (``list_users`` & co.),
  which returns the **Default** identity domain's users, groups, and dynamic
  groups.
- Every other identity domain, through the Identity Domains (SCIM) API. Domains
  are compartment-scoped resources, so they are discovered by listing domains
  in each compartment of the scan scope. Identities from these domains carry a
  ``domain`` field; the engine keys them as ``<domain>/<name>``.

Compartment scoping: with ``compartment_id`` set, policies and identity
domains are collected from that compartment and its subtree only. Tenancy-root
identities (the Default domain and secondary domains in the root compartment)
are reduced to the groups and dynamic groups those policies reference, plus the
members of those groups. The root is read best-effort in this mode, so a
credential limited to the compartment still yields the compartment's domains.

Also collects the optional identity-lifecycle enrichment the inventory builder
understands (see ``cloudsplaining/identity_inventory/oci.py``):

- ``auditEvents`` — CreateUser / CreateDynamicGroup events from the OCI Audit
  service (needs ``Allow group <X> to read audit-events in tenancy``), which
  power ``created_by``. An identity's creation event is logged in the
  compartment its identity domain lives in, so each identity's window is
  queried there (the root for Default-domain identities). Fails open: without
  the permission the key is emitted as an empty list and ``created_by`` stays
  null.
- ``idcsCreatedBy`` on each user — creator recorded by Identity Domains (needs
  ``Allow group <X> to read domains in tenancy`` plus user read on the domain).
  Stored on the user, so unlike audit events it never ages out of retention.
  Fails open: tenancies without Identity Domains keep audit-only attribution.

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
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from cloudsplaining.identity_inventory.oci import (
    CREATION_EVENT_SUFFIXES,
    USER_CAPABILITIES_EXTENSION,
    USER_STATE_EXTENSION,
)
from cloudsplaining.identity_inventory.parsing import parse_timestamp
from cloudsplaining.multicloud.collectors.base import Collector
from cloudsplaining.multicloud.oci.parser import (
    DEFAULT_DOMAIN,
    DOMAIN_SCOPED_SUBJECTS,
    parse_statement,
    qualified_name,
)

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
#: SCIM paging for Identity Domains listings; the cap bounds collect() wall
#: time on very large domains (10k resources covered).
_SCIM_PAGE_SIZE = 500
_SCIM_PAGE_LIMIT = 20

MFA_EXTENSION = "urn:ietf:params:scim:schemas:oracle:idcs:extension:mfa:User"

#: SCIM attributes requested per resource type. The extension attributes are
#: what the legacy API exposes natively, so domain users carry the same
#: lifecycle fields as Default-domain users.
_SCIM_USER_ATTRIBUTES = ",".join(
    [
        "userName",
        "ocid",
        "description",
        "emails",
        "meta",
        "idcsCreatedBy",
        f"{USER_STATE_EXTENSION}:lastSuccessfulLoginDate",
        f"{MFA_EXTENSION}:mfaStatus",
        f"{USER_CAPABILITIES_EXTENSION}:canUseConsolePassword",
        f"{USER_CAPABILITIES_EXTENSION}:canUseApiKeys",
    ]
)
_SCIM_GROUP_ATTRIBUTES = "displayName,ocid,description,members"
_SCIM_DYNAMIC_GROUP_ATTRIBUTES = "displayName,ocid,description,matchingRule,meta"

# The oci SDK maps SCIM extension schemas onto these attribute names.
_SDK_USER_STATE = "urn_ietf_params_scim_schemas_oracle_idcs_extension_user_state_user"
_SDK_MFA = "urn_ietf_params_scim_schemas_oracle_idcs_extension_mfa_user"
_SDK_CAPABILITIES = "urn_ietf_params_scim_schemas_oracle_idcs_extension_capabilities_user"


@dataclass
class _Identities:
    """Snapshot identity payloads; ``memberships`` is keyed the way the engine expects group names."""

    users: list[dict[str, Any]] = field(default_factory=list)
    groups: list[dict[str, Any]] = field(default_factory=list)
    dynamic_groups: list[dict[str, Any]] = field(default_factory=list)
    memberships: dict[str, list[str]] = field(default_factory=dict)
    #: identity id -> compartment whose audit log holds its creation event.
    compartments: dict[str, str] = field(default_factory=dict)

    def extend(self, other: _Identities) -> None:
        self.users.extend(other.users)
        self.groups.extend(other.groups)
        self.dynamic_groups.extend(other.dynamic_groups)
        self.memberships.update(other.memberships)
        self.compartments.update(other.compartments)


class OciCollector(Collector):
    name = "oci"
    extra = "oci"

    def __init__(
        self,
        tenancy_id: str | None = None,
        compartment_id: str | None = None,
        config_profile: str = "DEFAULT",
        config_file: str | None = None,
        client: Any | None = None,
        audit_client: Any | None = None,
        identity_domains_clients: dict[str, Any] | None = None,
        **_: Any,
    ) -> None:
        self._tenancy_id = tenancy_id
        self._compartment_id = compartment_id
        self._config_profile = config_profile
        self._config_file = config_file
        self._client = client
        self._audit_client = audit_client
        #: Injected Identity Domains clients keyed by domain URL (tests / callers
        #: that already hold clients); otherwise built from the OCI config.
        self._identity_domains_clients = identity_domains_clients
        self._oci_config: dict[str, Any] | None = None

    def _config(self, oci: Any) -> dict[str, Any]:
        if self._oci_config is None:
            kwargs: dict[str, str] = {"profile_name": self._config_profile}
            if self._config_file:
                kwargs["file_location"] = self._config_file
            self._oci_config = oci.config.from_file(**kwargs)
        return self._oci_config

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
        scoped = bool(self._compartment_id) and self._compartment_id != tenancy
        tree = self._compartment_tree(client, self._compartment_id if scoped else tenancy)
        policies = self._policies(client, tree)

        root = self._root_identities(client, tenancy, fail_open=scoped)
        if scoped:
            self._keep_referenced(policies, root)
        root.memberships.update(self._legacy_memberships(client, tenancy, root))
        if scoped:
            self._keep_members(root)
        inner = self._domain_identities(client, [cid for cid in tree if cid != tenancy])

        users = root.users + inner.users
        dynamic_groups = root.dynamic_groups + inner.dynamic_groups
        compartments = {**root.compartments, **inner.compartments}
        creation_times: dict[str, list[Any]] = {}
        for obj in users + dynamic_groups:
            creation_times.setdefault(compartments.get(obj["id"], tenancy), []).append(obj.get("timeCreated"))
        return {
            "account_id": tenancy,
            "compartment_id": self._compartment_id,
            "users": users,
            "groups": root.groups + inner.groups,
            "dynamicGroups": dynamic_groups,
            "policies": policies,
            "groupMemberships": {**root.memberships, **inner.memberships},
            "auditEvents": self._audit_events(creation_times),
        }

    # ------------------------------------------------------------- identities
    def _root_identities(self, client: Any, tenancy: str, *, fail_open: bool) -> _Identities:
        """Default-domain identities (legacy API) plus secondary domains that live in the root compartment."""
        root = _Identities()
        try:
            root.users = [self._user(u) for u in self._list(client.list_users, tenancy)]
            root.groups = [self._named(g) for g in self._list(client.list_groups, tenancy)]
            root.dynamic_groups = [self._dynamic_group(d) for d in self._list(client.list_dynamic_groups, tenancy)]
            root.compartments = {obj["id"]: tenancy for obj in root.users + root.dynamic_groups}
        except Exception as error:
            if not fail_open:
                raise
            logger.warning(
                "Tenancy-level identities unavailable; only identity domains inside the compartment are included: %s",
                error,
            )
        for domain, scim in self._domains(client, tenancy):
            if str(getattr(domain, "type", "") or "").upper() == "DEFAULT":
                # Already listed through the legacy API; the domain only adds idcsCreatedBy.
                self._merge_idcs_created_by(root.users, scim)
            else:
                root.extend(self._domain(domain, scim, tenancy))
        return root

    def _domain_identities(self, client: Any, compartments: list[str]) -> _Identities:
        """Identities of every identity domain located in ``compartments``."""
        found = _Identities()
        for compartment_id in compartments:
            for domain, scim in self._domains(client, compartment_id):
                found.extend(self._domain(domain, scim, compartment_id))
        return found

    def _domain(self, domain: Any, scim: Any, compartment_id: str) -> _Identities:
        """Users, groups (with members), and dynamic resource groups of one identity domain. Fails open per domain.

        ``compartment_id`` is where the domain lives; its identities' creation
        audit events are logged there.
        """
        name = str(getattr(domain, "display_name", None) or DEFAULT_DOMAIN)
        found = _Identities()
        try:
            found.users = [self._scim_user(u, name) for u in self._scim_list(scim.list_users, _SCIM_USER_ATTRIBUTES)]
            for group in self._scim_list(scim.list_groups, _SCIM_GROUP_ATTRIBUTES):
                found.groups.append(
                    {
                        "id": self._scim_id(group),
                        "name": group.display_name,
                        "description": getattr(group, "description", None),
                        "domain": name,
                    }
                )
                members = getattr(group, "members", None) or []
                found.memberships[qualified_name(group.display_name, name)] = [
                    m.name for m in members if getattr(m, "name", None)
                ]
            found.dynamic_groups = [
                self._scim_dynamic_group(d, name)
                for d in self._scim_list(scim.list_dynamic_resource_groups, _SCIM_DYNAMIC_GROUP_ATTRIBUTES)
            ]
        except Exception as error:
            logger.warning("Skipping identity domain %r (its identities are not in the snapshot): %s", name, error)
            return _Identities()
        found.compartments = {obj["id"]: compartment_id for obj in found.users + found.dynamic_groups}
        return found

    def _domains(self, client: Any, compartment_id: str) -> list[tuple[Any, Any]]:
        """(domain, IdentityDomainsClient) pairs for the domains in ``compartment_id``. Fails open."""
        try:
            domains = self._list(client.list_domains, compartment_id)
        except Exception as error:
            logger.warning("Skipping identity domains in compartment %s: %s", compartment_id, error)
            return []
        pairs = []
        for domain in domains:
            scim = self._domains_client(domain)
            if scim is not None:
                pairs.append((domain, scim))
        return pairs

    def _domains_client(self, domain: Any) -> Any | None:
        if self._identity_domains_clients is not None:
            url = getattr(domain, "url", None)
            return self._identity_domains_clients.get(str(url)) if url else None
        if self._client is not None:
            # Injected-identity-client mode has no OCI config to build clients from.
            return None
        oci = self._import("oci")
        return oci.identity_domains.IdentityDomainsClient(self._config(oci), domain.url)

    # --------------------------------------------------------- compartment scope
    @staticmethod
    def _keep_referenced(policies: list[dict[str, Any]], identities: _Identities) -> None:
        """Reduce groups / dynamic groups to those named (by domain-qualified name or OCID) in ``policies``."""
        wanted: dict[str, set[str]] = {"group": set(), "dynamic-group": set()}
        for policy in policies:
            for raw in policy["statements"]:
                parsed = parse_statement(raw, policy["name"])
                if parsed is None or parsed.subject_type not in DOMAIN_SCOPED_SUBJECTS:
                    continue
                ref = parsed.subject_ref
                key = ref.id if ref.id is not None else ref.name
                if key:
                    wanted[parsed.subject_type].add(key.lower())

        def keep(obj: dict[str, Any], kind: str) -> bool:
            return (
                str(obj["id"]).lower() in wanted[kind]
                or qualified_name(obj["name"], obj.get("domain")).lower() in wanted[kind]
            )

        identities.groups = [g for g in identities.groups if keep(g, "group")]
        identities.dynamic_groups = [d for d in identities.dynamic_groups if keep(d, "dynamic-group")]
        kept = {qualified_name(g["name"], g.get("domain")).lower() for g in identities.groups}
        identities.memberships = {k: v for k, v in identities.memberships.items() if qualified_name(k).lower() in kept}

    @staticmethod
    def _keep_members(identities: _Identities) -> None:
        """Reduce users to members of the remaining groups (matched within the group's domain)."""
        members: set[tuple[str, str]] = set()
        for key, names in identities.memberships.items():
            domain = qualified_name(key).partition("/")[0].lower()
            members.update((domain, name.lower()) for name in names)
        identities.users = [
            u
            for u in identities.users
            if ((u.get("domain") or DEFAULT_DOMAIN).lower(), str(u["name"]).lower()) in members
        ]

    # ------------------------------------------------------------- lifecycle
    def _audit_events(self, creation_times: dict[str, list[Any]]) -> list[dict[str, Any]]:
        """Identity-creation audit events; they power created_by in the identity inventory.

        ``creation_times`` maps a compartment to the timeCreated values of the
        identities whose creation events are logged there. Each compartment is
        queried in short windows around those times (where the events live)
        rather than over the whole retention window, which takes minutes on
        active tenancies. The page budget is shared across compartments.
        """
        try:
            client = self._audit_client_or_none()
            if client is None:
                return []
            events: list[dict[str, Any]] = []
            budget = _AUDIT_PAGE_LIMIT
            for compartment_id, times in creation_times.items():
                for start_time, end_time in self._creation_windows(times):
                    page = None
                    window_pages = 0
                    while budget > 0 and window_pages < _AUDIT_WINDOW_PAGE_LIMIT:
                        budget -= 1
                        window_pages += 1
                        kwargs: dict[str, Any] = {
                            "compartment_id": compartment_id,
                            "start_time": start_time,
                            "end_time": end_time,
                        }
                        if page:
                            kwargs["page"] = page
                        resp = client.list_events(**kwargs)
                        events.extend(event for event in map(self._creation_event, resp.data) if event is not None)
                        page = resp.next_page
                        if not page:
                            break
                    if budget <= 0:
                        break
                if budget <= 0:
                    break
            return events
        except Exception as error:
            logger.warning("Skipping auditEvents (created_by will be null): %s", error)
            return []

    def _merge_idcs_created_by(self, users: list[dict[str, Any]], scim: Any) -> None:
        """Annotate Default-domain users with the creator Identity Domains stores on them.

        ``idcsCreatedBy`` never ages out, so it attributes users created before
        the audit service's retention window began. Best-effort: without the
        permission, users keep audit-only attribution.
        """
        try:
            creators: dict[str, dict[str, Any]] = {}
            for user in self._scim_list(scim.list_users, _SCIM_USER_ATTRIBUTES):
                entry = self._idcs_created_by(user)
                if entry is None:
                    continue
                for key in (getattr(user, "ocid", None), getattr(user, "user_name", None)):
                    if key:
                        creators.setdefault(key, entry)
            for user in users:
                entry = creators.get(user.get("id") or "") or creators.get(user.get("name") or "")
                if entry:
                    user["idcsCreatedBy"] = entry
        except Exception as error:
            logger.warning("Skipping Identity Domains enrichment (idcsCreatedBy unavailable): %s", error)

    @staticmethod
    def _scim_list(fn: Any, attributes: str) -> list[Any]:
        items: list[Any] = []
        start_index = 1
        for _ in range(_SCIM_PAGE_LIMIT):
            resp = fn(attributes=attributes, count=_SCIM_PAGE_SIZE, start_index=start_index)
            resources = list(getattr(resp.data, "resources", None) or [])
            items.extend(resources)
            if len(resources) < _SCIM_PAGE_SIZE:
                break
            start_index += len(resources)
        return items

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

    def _policies(self, client: Any, compartments: list[str]) -> list[dict[str, Any]]:
        """Policies attached in each of ``compartments``."""
        out: list[dict[str, Any]] = []
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

    def _compartment_tree(self, client: Any, root: str) -> list[str]:
        """``root`` (tenancy or compartment OCID) followed by its descendants, breadth-first.

        OCI only honours ``compartment_id_in_subtree`` when listing from the
        tenancy, so walk one level at a time; that works from any start point.
        """
        tree = [root]
        queue = [root]
        while queue:
            parent = queue.pop(0)
            for child in self._list(client.list_compartments, parent):
                if child.id not in tree:
                    tree.append(child.id)
                    queue.append(child.id)
        return tree

    def _legacy_memberships(self, client: Any, tenancy: str, root: _Identities) -> dict[str, list[str]]:
        """Memberships of the Default-domain groups, keyed by bare group name (the engine assumes Default)."""
        user_name = {u["id"]: u["name"] for u in root.users}
        memberships: dict[str, list[str]] = {}
        for group in root.groups:
            if group.get("domain"):
                continue  # secondary-domain groups ship their members with the group
            links = self._list_memberships(client, tenancy, group["id"])
            names = [user_name.get(link.user_id) for link in links]
            memberships[group["name"]] = [n for n in names if n]
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

    # ------------------------------------------------------------- SCIM shapes
    @staticmethod
    def _scim_id(obj: Any) -> str:
        """The IAM OCID (what policies reference); the SCIM ``id`` is a domain-local identifier."""
        return str(getattr(obj, "ocid", None) or getattr(obj, "id", None) or "")

    @classmethod
    def _scim_user(cls, obj: Any, domain: str) -> dict[str, Any]:
        """A domain user in the same shape as a legacy ``_user`` payload, plus ``domain``."""
        state = getattr(obj, _SDK_USER_STATE, None)
        mfa = getattr(obj, _SDK_MFA, None)
        capabilities = getattr(obj, _SDK_CAPABILITIES, None)
        emails = list(getattr(obj, "emails", None) or [])
        primary = next((e for e in emails if getattr(e, "primary", False)), emails[0] if emails else None)
        payload: dict[str, Any] = {
            "id": cls._scim_id(obj),
            "name": getattr(obj, "user_name", None),
            "description": getattr(obj, "description", None),
            "email": getattr(primary, "value", None),
            "timeCreated": parse_timestamp(getattr(getattr(obj, "meta", None), "created", None)),
            "lastSuccessfulLoginTime": parse_timestamp(getattr(state, "last_successful_login_date", None)),
            "isMfaActivated": str(getattr(mfa, "mfa_status", None) or "").upper() == "ENROLLED",
            "capabilities": (
                {
                    "canUseConsolePassword": getattr(capabilities, "can_use_console_password", None),
                    "canUseApiKeys": getattr(capabilities, "can_use_api_keys", None),
                }
                if capabilities is not None
                else None
            ),
            "domain": domain,
        }
        created_by = cls._idcs_created_by(obj)
        if created_by is not None:
            payload["idcsCreatedBy"] = created_by
        return payload

    @classmethod
    def _scim_dynamic_group(cls, obj: Any, domain: str) -> dict[str, Any]:
        return {
            "id": cls._scim_id(obj),
            "name": obj.display_name,
            "matching-rule": getattr(obj, "matching_rule", None),
            "timeCreated": parse_timestamp(getattr(getattr(obj, "meta", None), "created", None)),
            "domain": domain,
        }

    @staticmethod
    def _idcs_created_by(obj: Any) -> dict[str, Any] | None:
        created_by = getattr(obj, "idcs_created_by", None)
        if created_by is None:
            return None
        return {"display": getattr(created_by, "display", None), "value": getattr(created_by, "value", None)}
