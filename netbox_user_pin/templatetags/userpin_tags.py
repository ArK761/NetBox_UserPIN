from django import template

from ..build import plugin_build

register = template.Library()


@register.inclusion_tag('netbox_user_pin/inc/build_badge.html')
def pin_build():
    return {'build': plugin_build()}
