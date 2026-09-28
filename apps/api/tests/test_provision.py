"""Provisioning API: one trusted outside app creates customer workspaces + keys."""

from __future__ import annotations

import pytest
from django.test import Client, override_settings
from django.utils import timezone

from apps.members.models import OrgMembership

TOKEN = "t" * 48
HOST = "lexi.example.com"


@pytest.fixture
def operator(db):
    from apps.accounts.models import User

    return User.objects.create_user(
        email="operator@example.com", password="x-pass-123", name="Op", tos_accepted_at=timezone.now()
    )


@pytest.fixture
def org(db, operator):
    from apps.organizations.models import Organization

    o = Organization.objects.create(name="House Org")
    OrgMembership.objects.create(user=operator, organization=o, org_role=OrgMembership.OrgRole.OWNER)
    return o


@pytest.fixture
def configured(org):
    with override_settings(
        PROVISIONING_TOKEN=TOKEN,
        PROVISION_ORG_ID=str(org.id),
        PROVISION_OPERATOR_EMAIL="operator@example.com",
        PROVISION_RETURN_HOSTS=[HOST],
    ):
        yield


def _post(path, body, token=TOKEN):
    import json

    headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}
    return Client().post(
        f"/api/v1/provision{path}", data=json.dumps(body), content_type="application/json", secure=True, **headers
    )


def _api(path, key):
    return Client().get(f"/api/v1{path}/", HTTP_AUTHORIZATION=f"Bearer {key}", secure=True)


# --- auth -------------------------------------------------------------------


@pytest.mark.django_db
def test_no_token_configured_refuses_everything(org):
    with override_settings(PROVISIONING_TOKEN=""):
        assert _post("/workspaces", {"external_id": "t1", "name": "A"}, token="").status_code == 401
        assert _post("/workspaces", {"external_id": "t1", "name": "A"}, token="").status_code == 401  # empty bearer
        assert _post("/workspaces", {"external_id": "t1", "name": "A"}, token="x" * 48).status_code == 401


@pytest.mark.django_db
def test_short_token_setting_is_treated_as_off(org):
    with override_settings(PROVISIONING_TOKEN="short"):
        assert _post("/workspaces", {"external_id": "t1", "name": "A"}, token="short").status_code == 401


@pytest.mark.django_db
def test_wrong_token_rejected(configured):
    assert _post("/workspaces", {"external_id": "t1", "name": "A"}, token="w" * 48).status_code == 401


@pytest.mark.django_db
def test_regular_api_key_cannot_provision(configured, org, operator):
    """An ordinary workspace key must not open the operator door."""
    body = _post("/workspaces", {"external_id": "t1", "name": "A"}).json()
    assert _post("/workspaces", {"external_id": "t2", "name": "B"}, token=body["api_key"]).status_code == 401


@pytest.mark.django_db
def test_plain_http_refused(configured):
    import json

    r = Client().post(
        "/api/v1/provision/workspaces",
        data=json.dumps({"external_id": "t1", "name": "A"}),
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {TOKEN}",
    )
    assert r.status_code == 401


@pytest.mark.django_db
def test_org_id_optional_when_operator_has_one_org(operator):
    """Signup gives every user one org; with PROVISION_ORG_ID blank that org is used."""
    from apps.workspaces.models import Workspace

    (only_org,) = OrgMembership.objects.filter(user=operator).values_list("organization_id", flat=True)
    with override_settings(
        PROVISIONING_TOKEN=TOKEN, PROVISION_ORG_ID="", PROVISION_OPERATOR_EMAIL="operator@example.com"
    ):
        r = _post("/workspaces", {"external_id": "solo", "name": "Solo"})
        assert r.status_code == 200, r.content
        assert Workspace.objects.get(id=r.json()["workspace_id"]).organization_id == only_org


@pytest.mark.django_db
def test_org_id_required_when_operator_has_several_orgs(org, operator):
    from apps.organizations.models import Organization

    other = Organization.objects.create(name="Second Org")
    OrgMembership.objects.create(user=operator, organization=other, org_role=OrgMembership.OrgRole.OWNER)
    with override_settings(
        PROVISIONING_TOKEN=TOKEN, PROVISION_ORG_ID="", PROVISION_OPERATOR_EMAIL="operator@example.com"
    ):
        assert _post("/workspaces", {"external_id": "amb", "name": "A"}).status_code == 503


@pytest.mark.django_db
def test_unconfigured_org_is_503(org):
    with override_settings(PROVISIONING_TOKEN=TOKEN, PROVISION_ORG_ID="", PROVISION_OPERATOR_EMAIL=""):
        assert _post("/workspaces", {"external_id": "t1", "name": "A"}).status_code == 503


# --- create / idempotency / rotate -----------------------------------------


@pytest.mark.django_db
def test_create_is_idempotent_and_key_works(configured, org):
    from apps.workspaces.models import Workspace

    r1 = _post("/workspaces", {"external_id": "tenant-1", "name": "Ace Roofing", "timezone": "America/New_York"})
    assert r1.status_code == 200, r1.content
    b1 = r1.json()
    assert b1["created"] is True and b1["api_key"].startswith("bb_studio_")

    r2 = _post("/workspaces", {"external_id": "tenant-1", "name": "Ace Roofing"})
    b2 = r2.json()
    assert b2["created"] is False and b2["api_key"] is None
    assert b2["workspace_id"] == b1["workspace_id"]
    assert Workspace.objects.filter(organization=org).count() == 1

    me = _api("/me", b1["api_key"])
    assert me.status_code == 200, me.content


@pytest.mark.django_db
def test_bad_external_id_rejected(configured):
    assert _post("/workspaces", {"external_id": "bad id!", "name": "A"}).status_code == 422
    assert _post("/workspaces", {"external_id": "", "name": "A"}).status_code == 422


@pytest.mark.django_db
def test_rotate_revokes_old_key(configured):
    b1 = _post("/workspaces", {"external_id": "tenant-r", "name": "R"}).json()
    old = b1["api_key"]
    assert _api("/me", old).status_code == 200
    b2 = _post("/workspaces", {"external_id": "tenant-r", "name": "R", "rotate_key": True}).json()
    assert b2["api_key"] and b2["api_key"] != old
    assert _api("/me", old).status_code == 401
    assert _api("/me", b2["api_key"]).status_code == 200


@pytest.mark.django_db
def test_all_accounts_key_sees_accounts_connected_later(configured):
    from apps.social_accounts.models import SocialAccount

    b = _post("/workspaces", {"external_id": "tenant-a", "name": "A"}).json()
    other = _post("/workspaces", {"external_id": "tenant-b", "name": "B"}).json()
    assert "Ace FB" not in _api("/accounts", b["api_key"]).content.decode()

    SocialAccount.objects.create(
        workspace_id=b["workspace_id"],
        platform="facebook",
        account_platform_id="fb-1",
        account_name="Ace FB",
        connection_status="connected",
    )
    SocialAccount.objects.create(
        workspace_id=other["workspace_id"],
        platform="facebook",
        account_platform_id="fb-2",
        account_name="Other FB",
        connection_status="connected",
    )
    text = _api("/accounts", b["api_key"]).content.decode()
    assert "Ace FB" in text
    assert "Other FB" not in text  # never leaks across workspaces


# --- connection links ---------------------------------------------------------


@pytest.mark.django_db
def test_connection_link_flow(configured):
    from apps.onboarding.models import ConnectionLink

    ws = _post("/workspaces", {"external_id": "tenant-c", "name": "C"}).json()["workspace_id"]
    ret = f"https://{HOST}/marketing"
    r1 = _post(f"/workspaces/{ws}/connection-link", {"return_url": ret})
    assert r1.status_code == 200, r1.content
    assert "/onboarding/connect/" in r1.json()["url"]
    r2 = _post(f"/workspaces/{ws}/connection-link", {"return_url": ret})
    links = ConnectionLink.objects.filter(workspace_id=ws)
    assert links.count() == 2
    assert links.filter(revoked_at__isnull=True).count() == 1  # only the newest works
    assert links.get(revoked_at__isnull=True).return_url == ret
    assert r2.json()["url"] != r1.json()["url"]


@pytest.mark.django_db
def test_connection_link_return_host_checked(configured):
    ws = _post("/workspaces", {"external_id": "tenant-d", "name": "D"}).json()["workspace_id"]
    assert _post(f"/workspaces/{ws}/connection-link", {"return_url": "https://evil.example.com/x"}).status_code == 422
    assert _post(f"/workspaces/{ws}/connection-link", {"return_url": f"http://{HOST}/x"}).status_code == 422
    assert _post(f"/workspaces/{ws}/connection-link", {}).status_code == 200  # no return is fine


@pytest.mark.django_db
def test_connection_link_only_for_provisioned(configured, org):
    from apps.workspaces.models import Workspace

    plain = Workspace.objects.create(name="Hand-made", organization=org)
    assert _post(f"/workspaces/{plain.id}/connection-link", {}).status_code == 404


@pytest.mark.django_db
def test_success_page_offers_return(configured):
    from apps.onboarding.models import ConnectionLink

    ws = _post("/workspaces", {"external_id": "tenant-e", "name": "E"}).json()["workspace_id"]
    _post(f"/workspaces/{ws}/connection-link", {"return_url": f"https://{HOST}/marketing"})
    link = ConnectionLink.objects.get(workspace_id=ws, revoked_at__isnull=True)
    from django.urls import reverse

    page = Client().post(reverse("onboarding:connection_done", kwargs={"token": link.token}), secure=True)
    assert page.status_code == 200
    assert f"https://{HOST}/marketing" in page.content.decode()


@pytest.mark.django_db
def test_ping(configured, org):
    ok = Client().get("/api/v1/provision/ping", HTTP_AUTHORIZATION=f"Bearer {TOKEN}", secure=True)
    assert ok.status_code == 200 and ok.json()["organization"] == "House Org"
    bad = Client().get("/api/v1/provision/ping", HTTP_AUTHORIZATION=f"Bearer {'w' * 48}", secure=True)
    assert bad.status_code == 401
