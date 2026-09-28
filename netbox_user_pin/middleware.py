"""
Activates the language chosen in the PIN settings for the plugin's own pages (the rest of NetBox keeps its
language).
"""
from django.urls import reverse
from django.utils import translation

__all__ = ('PluginLanguageMiddleware',)


class PluginLanguageMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self._prefix = None

    def _plugin_prefix(self):
        if self._prefix is None:
            self._prefix = reverse('plugins:netbox_user_pin:my_pin')
        return self._prefix

    def __call__(self, request):
        if not request.path.startswith(self._plugin_prefix()):
            return self.get_response(request)
        from .service import get_settings
        with translation.override(get_settings().language or 'en'):
            response = self.get_response(request)
            if hasattr(response, 'render') and not getattr(response, 'is_rendered', True):
                response.render()
            return response
