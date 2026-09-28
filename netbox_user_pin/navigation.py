from django.utils.translation import gettext_lazy as _
from netbox.plugins import PluginMenu, PluginMenuItem

menu = PluginMenu(
    label='User PIN',
    icon_class='mdi mdi-dialpad',
    groups=(
        (_('My PIN'), (
            PluginMenuItem(link='plugins:netbox_user_pin:my_pin', link_text=_('My PIN'), auth_required=True),
            PluginMenuItem(link='plugins:netbox_user_pin:test', link_text=_('Test unlock'), auth_required=True),
        )),
        (_('Administration'), (
            PluginMenuItem(
                link='plugins:netbox_user_pin:user_list', link_text=_('Users'),
                permissions=['netbox_user_pin.view_userpin'],
            ),
            PluginMenuItem(
                link='plugins:netbox_user_pin:approval_list', link_text=_('Approvals (four eyes)'),
                permissions=['netbox_user_pin.view_userpin'],
            ),
            PluginMenuItem(
                link='plugins:netbox_user_pin:event_list', link_text=_('Audit log'),
                permissions=['netbox_user_pin.view_pinevent'],
            ),
            PluginMenuItem(
                link='plugins:netbox_user_pin:settings', link_text=_('Settings'),
                permissions=['netbox_user_pin.view_pinsettings'],
            ),
            PluginMenuItem(
                link='plugins:netbox_user_pin:mail', link_text=_('Mail'),
                permissions=['netbox_user_pin.view_pinsettings'],
            ),
            PluginMenuItem(
                # add_pinsettings is only ever held by superusers (the master)
                link='plugins:netbox_user_pin:delegates', link_text=_('Delegates'),
                permissions=['netbox_user_pin.add_pinsettings'],
            ),
        )),
    ),
)
