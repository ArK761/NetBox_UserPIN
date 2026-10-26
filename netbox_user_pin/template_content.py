"""
Global page additions: a badge next to "My PIN" in the left menu with the days until the PIN must be changed.
"""
import json

from django.urls import reverse
from django.utils import timezone, translation
from django.utils.translation import gettext as _
from netbox.plugins import PluginTemplateExtension

__all__ = ('template_extensions',)


class PinMenuBadge(PluginTemplateExtension):
    """No models = global: head() is rendered on every NetBox page."""

    def head(self):
        request = self.context.get('request')
        user = getattr(request, 'user', None)
        if user is None or not user.is_authenticated:
            return ''
        from . import service
        try:
            settings = service.get_settings()
            if not service.is_allowed(user, settings):
                return ''
            from .models import UserPin
            user_pin = UserPin.objects.filter(user=user).first()
            with translation.override(settings.language or 'en'):
                badge = self._badge(service, settings, user_pin)
        except Exception:  # never break a NetBox page because of the badge
            return ''
        if badge is None:
            return ''
        data = json.dumps({'href': reverse('plugins:netbox_user_pin:my_pin'), **badge})
        return (
            '<script>document.addEventListener("DOMContentLoaded",function(){'
            f'var b={data};'
            'document.querySelectorAll(\'a[href="\'+b.href+\'"]\').forEach(function(a){'
            'if(a.querySelector(".pin-days"))return;var s=document.createElement("span");'
            's.className="pin-days badge ms-2 text-bg-"+b.color;s.textContent=b.text;s.title=b.title;'
            'a.appendChild(s);});});</script>'
        )

    @staticmethod
    def _badge(service, settings, user_pin):
        if user_pin is None or not user_pin.is_set:
            return {'text': _('set up'), 'color': 'orange', 'title': _('You have no PIN yet.')}
        if user_pin.suspended:
            return {'text': '!', 'color': 'red', 'title': _('Your PIN is suspended.')}
        if user_pin.must_change:
            return {'text': _('change'), 'color': 'red', 'title': _('Your PIN must be changed.')}
        expires = service.pin_expires_at(user_pin, settings)
        if expires is None:
            return None
        days = (expires - timezone.now()).days
        if days < 0:
            return {'text': _('change'), 'color': 'red', 'title': _('Your PIN has expired.')}
        title = _('PIN valid for {days} more days (until {date}).').format(
            days=days, date=timezone.localtime(expires).strftime('%d.%m.%Y'))
        color = 'yellow' if days <= settings.warn_days else 'green'
        return {'text': _('{days} d').format(days=days), 'color': color, 'title': title}


template_extensions = [PinMenuBadge]
