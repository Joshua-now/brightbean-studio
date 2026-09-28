"""SIGNUP_OPEN=false closes public self-signup but keeps invitations working."""

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.accounts.models import User
from apps.members.models import Invitation
from apps.organizations.models import Organization


def _post_signup(client, email):
    return client.post(
        reverse("account_signup"),
        {"email": email, "password1": "a-Long-pass-9981!", "password2": "a-Long-pass-9981!"},
    )


def _invite(email, *, expired=False):
    org = Organization.objects.create(name="Acme")
    delta = timedelta(days=-1) if expired else timedelta(days=7)
    return Invitation.objects.create(organization=org, email=email, expires_at=timezone.now() + delta)


@pytest.mark.django_db
def test_signup_open_by_default(client, settings):
    settings.SIGNUP_OPEN = True
    resp = client.get(reverse("account_signup"))
    assert resp.status_code == 200
    assert b"by invitation" not in resp.content
    assert b"Sign up" in client.get(reverse("account_login")).content


@pytest.mark.django_db
def test_closed_signup_blocks_strangers(client, settings):
    settings.SIGNUP_OPEN = False
    resp = client.get(reverse("account_signup"))
    assert b"by invitation" in resp.content
    _post_signup(client, "stranger@example.com")
    assert not User.objects.filter(email="stranger@example.com").exists()
    assert b"Don&#x27;t have an account" not in client.get(reverse("account_login")).content


@pytest.mark.django_db
def test_closed_signup_allows_pending_invite(client, settings):
    settings.SIGNUP_OPEN = False
    inv = _invite("teammate@example.com")
    session = client.session
    session["pending_invite_token"] = inv.token
    session.save()
    assert b"by invitation" not in client.get(reverse("account_signup")).content
    _post_signup(client, "teammate@example.com")
    assert User.objects.filter(email="teammate@example.com").exists()


@pytest.mark.django_db
def test_closed_signup_rejects_expired_invite(client, settings):
    settings.SIGNUP_OPEN = False
    inv = _invite("late@example.com", expired=True)
    session = client.session
    session["pending_invite_token"] = inv.token
    session.save()
    assert b"by invitation" in client.get(reverse("account_signup")).content
    _post_signup(client, "late@example.com")
    assert not User.objects.filter(email="late@example.com").exists()
