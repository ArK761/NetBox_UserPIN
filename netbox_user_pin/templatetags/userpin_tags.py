from django import template

from ..build import plugin_build

register = template.Library()


@register.inclusion_tag('netbox_user_pin/inc/build_badge.html', takes_context=True)
def pin_build(context):
    """The version badge: for the administrators only (not for PIN-only people, not before signing in)."""
    request = context.get('request')
    user = getattr(request, 'user', None)
    shown = False
    if getattr(user, 'is_authenticated', False):
        from .. import areas, guests, roles
        shown = not guests.is_guest(user) and (user.is_superuser or roles.is_manager(user) or areas.is_keeper(user)
                                               or areas.administers_any(user))
    return {'build': plugin_build() if shown else None}
