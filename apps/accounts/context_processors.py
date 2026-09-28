from django.conf import settings


def signup_flag(request):
    """Expose SIGNUP_OPEN so auth templates can hide the public sign-up link."""
    return {"signup_open": getattr(settings, "SIGNUP_OPEN", True)}
