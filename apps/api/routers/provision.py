"""Provisioning API - lets ONE trusted outside system (AITeammate / Lexi) set up
customers without anyone logging in to Studio.

Everything here is behind a single shared service token (PROVISIONING_TOKEN,
compared in constant time). With no token configured every route answers 401,
so an install that doesn't use provisioning exposes nothing.

What it does:
  * POST /provision/workspaces
        Create (or return) the workspace for an outside customer id, owned by
        the operator account, plus a workspace-wide API key for it. Idempotent
        by ``external_id``: calling twice never makes a second workspace. The
        key's plaintext is returned only when a key is minted (first call, or
        ``rotate_key=true``, which revokes the old provisioned keys first).
  * POST /provision/workspaces/{workspace_id}/connection-link
        A short-lived public "connect your accounts" link for that workspace,
        optionally sending the person back to ``return_url`` when done. The
        return host must be in PROVISION_RETURN_HOSTS. Older links made here
        for the same workspace are revoked, so only the newest one works.

Only workspaces this API created can be reached through it.
"""

from __future__ import annotations

import hmac
import logging
from datetime import timedelta
from urllib.parse import urlparse

from django.conf import settings
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils import timezone
from ninja import Router, Schema
from ninja.errors import HttpError
from ninja.security import HttpBearer

from apps.api.models import ProvisionedWorkspace
from apps.api_keys.models import ApiKey
from apps.api_keys.services import issue_api_key, revoke_api_key
from apps.members.models import WorkspaceMembership
from apps.onboarding.models import ConnectionLink
from apps.organizations.models import Organization
from apps.workspaces.models import Workspace

LOG = logging.getLogger(__name__)

router = Router(tags=["provision"])

PROVISIONED_KEY_NAME = "Provisioned (AITeammate)"
PROVISIONED_KEY_PERMISSIONS = ["create_posts", "publish_directly", "upload_media", "view_analytics"]
LINK_TTL = timedelta(hours=2)


class ProvisionAuth(HttpBearer):
    """Bearer == settings.PROVISIONING_TOKEN (constant-time). Unset = always refuse."""

    def authenticate(self, request, token: str):
        from apps.api.limits import is_failed_auth_ip_blocked, record_failed_auth

        expected = (getattr(settings, "PROVISIONING_TOKEN", "") or "").strip()
        if not expected or len(expected) < 32:
            return None
        # Same pre-auth defenses as the key path: IP throttle + no plaintext bearers in prod.
        if is_failed_auth_ip_blocked(request):
            return None
        if not request.is_secure() and not settings.DEBUG:
            LOG.warning("Provisioning auth rejected: request is not HTTPS.")
            record_failed_auth(request)
            return None
        if hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8")):
            return True
        LOG.info("Provisioning auth rejected.")
        record_failed_auth(request)
        return None


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class WorkspaceIn(Schema):
    external_id: str
    name: str
    timezone: str = ""
    rotate_key: bool = False


class WorkspaceOut(Schema):
    workspace_id: str
    created: bool
    api_key: str | None = None  # plaintext, only when a key was minted by THIS call


class LinkIn(Schema):
    return_url: str = ""


class LinkOut(Schema):
    url: str
    expires_at: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _operator_and_org():
    """The org new workspaces live in and the account that owns them."""
    org_id = (getattr(settings, "PROVISION_ORG_ID", "") or "").strip()
    email = (getattr(settings, "PROVISION_OPERATOR_EMAIL", "") or "").strip().lower()
    if not org_id or not email:
        raise HttpError(503, "Provisioning is not configured on this install.")
    org = Organization.objects.filter(id=org_id).first()
    if org is None:
        raise HttpError(503, "PROVISION_ORG_ID does not match an organization.")
    from apps.accounts.models import User
    from apps.members.models import OrgMembership

    operator = User.objects.filter(email__iexact=email).first()
    if operator is None or not OrgMembership.objects.filter(user=operator, organization=org).exists():
        raise HttpError(503, "PROVISION_OPERATOR_EMAIL is not a member of the provisioning organization.")
    return org, operator


def _clean_external_id(raw: str) -> str:
    ext = (raw or "").strip()
    if not ext or len(ext) > 64 or not all(c.isalnum() or c in "-_:." for c in ext):
        raise HttpError(422, "external_id must be 1-64 characters: letters, digits, - _ : .")
    return ext


def _mint_key(workspace: Workspace, operator) -> str:
    issued = issue_api_key(
        workspace=workspace,
        social_accounts=[],
        issued_by=operator,
        name=PROVISIONED_KEY_NAME,
        permissions=PROVISIONED_KEY_PERMISSIONS,
        all_workspace_accounts=True,
    )
    return issued.plaintext_token


def _allowed_return(url: str) -> str:
    if not url:
        return ""
    hosts = {h.strip().lower() for h in (getattr(settings, "PROVISION_RETURN_HOSTS", []) or []) if h.strip()}
    parsed = urlparse(url)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in hosts:
        raise HttpError(422, "return_url must be https on an allowed host (PROVISION_RETURN_HOSTS).")
    return url[:500]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/workspaces", response=WorkspaceOut, summary="Create or fetch a provisioned workspace")
def provision_workspace(request, payload: WorkspaceIn):
    ext = _clean_external_id(payload.external_id)
    name = (payload.name or "").strip()[:100] or ext
    org, operator = _operator_and_org()

    existing = ProvisionedWorkspace.objects.select_related("workspace").filter(external_id=ext).first()
    if existing is not None:
        ws = existing.workspace
        if ws.organization_id != org.id:
            raise HttpError(409, "That external_id belongs to another organization.")
        key = None
        if payload.rotate_key:
            with transaction.atomic():
                for old in ApiKey.objects.filter(workspace=ws, name=PROVISIONED_KEY_NAME, revoked_at__isnull=True):
                    revoke_api_key(old)  # also busts the verification cache
                key = _mint_key(ws, operator)
        return WorkspaceOut(workspace_id=str(ws.id), created=False, api_key=key)

    try:
        with transaction.atomic():
            ws = Workspace.objects.create(
                organization=org, name=name, **({"timezone": payload.timezone} if payload.timezone else {})
            )
            WorkspaceMembership.objects.create(
                user=operator, workspace=ws, workspace_role=WorkspaceMembership.WorkspaceRole.OWNER
            )
            ProvisionedWorkspace.objects.create(external_id=ext, workspace=ws)
            key = _mint_key(ws, operator)
    except IntegrityError:
        # A concurrent call for the same external_id won the race; hand back its workspace.
        existing = ProvisionedWorkspace.objects.filter(external_id=ext).first()
        if existing is None:
            raise
        return WorkspaceOut(workspace_id=str(existing.workspace_id), created=False, api_key=None)
    except ValueError as exc:  # issue_api_key refused (e.g. operator lacks manage_api_keys)
        raise HttpError(503, f"Couldn't issue the workspace key: {exc}") from exc
    LOG.info("Provisioned workspace %s for external id %s", ws.id, ext)
    return WorkspaceOut(workspace_id=str(ws.id), created=True, api_key=key)


@router.post(
    "/workspaces/{workspace_id}/connection-link",
    response=LinkOut,
    summary="Make a connect-your-accounts link for a provisioned workspace",
)
def connection_link(request, workspace_id: str, payload: LinkIn):
    prov = ProvisionedWorkspace.objects.select_related("workspace").filter(workspace_id=workspace_id).first()
    if prov is None:
        raise HttpError(404, "Not a provisioned workspace.")
    return_url = _allowed_return(payload.return_url)
    _, operator = _operator_and_org()
    now = timezone.now()
    with transaction.atomic():
        # Only the newest link works - an old one sitting in someone's history can't be reused.
        ConnectionLink.objects.filter(
            workspace=prov.workspace, created_by=operator, revoked_at__isnull=True, expires_at__gt=now
        ).update(revoked_at=now)
        link = ConnectionLink.objects.create(
            workspace=prov.workspace, created_by=operator, expires_at=now + LINK_TTL, return_url=return_url
        )
    url = request.build_absolute_uri(reverse("onboarding:connection_page", kwargs={"token": link.token}))
    return LinkOut(url=url, expires_at=link.expires_at.isoformat())
