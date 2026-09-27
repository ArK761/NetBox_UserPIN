from netbox.plugins import PluginMenu, PluginMenuItem

menu = PluginMenu(
    label='User PIN',
    icon_class='mdi mdi-dialpad',
    groups=(
        ('My PIN', (
            PluginMenuItem(link='plugins:netbox_user_pin:my_pin', link_text='My PIN', auth_required=True),
            PluginMenuItem(link='plugins:netbox_user_pin:test', link_text='Test unlock', auth_required=True),
        )),
        ('Administration', (
            PluginMenuItem(
                link='plugins:netbox_user_pin:user_list', link_text='Users',
                permissions=['netbox_user_pin.view_userpin'],
            ),
            PluginMenuItem(
                link='plugins:netbox_user_pin:event_list', link_text='Audit log',
                permissions=['netbox_user_pin.view_pinevent'],
            ),
            PluginMenuItem(
                link='plugins:netbox_user_pin:settings', link_text='Settings',
                permissions=['netbox_user_pin.view_pinsettings'],
            ),
            PluginMenuItem(
                # add_pinsettings is only ever held by superusers (the master)
                link='plugins:netbox_user_pin:delegates', link_text='Delegates',
                permissions=['netbox_user_pin.add_pinsettings'],
            ),
        )),
    ),
)
