from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings

from apps.accounts.models import OAuthConnection
from apps.common.mail import transactional


def signup_allowed(request) -> bool:
    """Whether a NEW account may be created on this request.

    ``SIGNUP_OPEN`` (env, default True = upstream behaviour) controls public
    self-signup. When it is off, the only way in is a pending, unexpired
    workspace invitation in the session (set by ``accept_invite``), so an
    owner can still bring team members in while strangers who find the URL
    cannot create an organization on this install. Existing users signing in
    are never affected - allauth only asks this for new accounts.
    """
    if getattr(settings, "SIGNUP_OPEN", True):
        return True
    token = request.session.get("pending_invite_token") if request is not None else None
    if not token:
        return False
    from apps.members.models import Invitation

    invitation = Invitation.objects.filter(token=token, accepted_at__isnull=True).first()
    return bool(invitation and not invitation.is_expired)


class AccountAdapter(DefaultAccountAdapter):
    """Marks allauth's own mail as transactional.

    Password resets, email confirmations and login codes are mail a person is
    sitting in front of waiting for. Without this they would carry the default
    ``notification`` class and be subject to the per-recipient cap in
    ``apps.common.mail`` — so a user who had already received their allowance of
    publish-failure notices that hour could not reset their own password. The
    global daily cap still applies; nothing bypasses that.

    ``render_mail`` is the single seam every allauth email passes through, so
    overriding it here covers all of them without touching a template.
    """

    def is_open_for_signup(self, request):
        return signup_allowed(request)

    def render_mail(self, template_prefix, email, context, headers=None):
        return super().render_mail(
            template_prefix,
            email,
            context,
            headers={**(headers or {}), **transactional()},
        )


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    """Custom adapter that syncs Google social logins to OAuthConnection."""

    def is_open_for_signup(self, request, sociallogin):
        return signup_allowed(request)

    def populate_user(self, request, sociallogin, data):
        """Set user.name from Google profile (custom User model has 'name', not first/last)."""
        user = super().populate_user(request, sociallogin, data)
        first_name = data.get("first_name", "")
        last_name = data.get("last_name", "")
        full_name = f"{first_name} {last_name}".strip()
        if full_name and not user.name:
            user.name = full_name
        return user

    def save_user(self, request, sociallogin, form=None):
        """Create OAuthConnection after saving a new social signup."""
        user = super().save_user(request, sociallogin, form)
        self._sync_oauth_connection(user, sociallogin)
        return user

    def pre_social_login(self, request, sociallogin):
        """Sync OAuthConnection for returning users and auto-connected accounts."""
        super().pre_social_login(request, sociallogin)
        if sociallogin.is_existing:
            self._sync_oauth_connection(sociallogin.user, sociallogin)

    def _sync_oauth_connection(self, user, sociallogin):
        account = sociallogin.account
        if account.provider != "google":
            return
        provider_email = ""
        for ea in sociallogin.email_addresses:
            provider_email = ea.email
            break
        OAuthConnection.objects.update_or_create(
            provider=OAuthConnection.Provider.GOOGLE,
            provider_user_id=account.uid,
            defaults={"user": user, "provider_email": provider_email},
        )
