"""
 This file simply creates the navigation menu items for the D3C-Plugin in NetBox.
"""

from django.conf import settings
from extras.plugins import PluginMenu, PluginMenuButton, PluginMenuItem
from utilities.choices import ButtonColorChoices

plugin_settings = settings.PLUGINS_CONFIG["d3c"]

finding_buttons = [
    PluginMenuButton(
        link='plugins:d3c:devicefinding_add',
        title='Add',
        icon_class='mdi mdi-plus-thick',
        color=ButtonColorChoices.GREEN
    ),
    PluginMenuButton(
        link='plugins:d3c:devicefinding_std_import',
        title='Import',
        icon_class='mdi mdi-upload',
        color=ButtonColorChoices.CYAN
    ),
    PluginMenuButton(
        link='plugins:d3c:devicefinding_import',
        title='Import/Mapping',
        icon_class='mdi mdi-upload',
        color=ButtonColorChoices.BLUE
    )
]

findingItem = PluginMenuItem(
    link='plugins:d3c:devicefinding_list',
    link_text='DeviceFindings',
    buttons=finding_buttons
)

###
communication_buttons = [
    PluginMenuButton(
        link='plugins:d3c:communication_add',
        title='Add',
        icon_class='mdi mdi-plus-thick',
        color=ButtonColorChoices.GREEN
    ),
    PluginMenuButton(
        link='plugins:d3c:communication_import',
        title='Import',
        icon_class='mdi mdi-upload',
        color=ButtonColorChoices.CYAN
    )
]

communicationItem = PluginMenuItem(
    link='plugins:d3c:communication_list',
    link_text='Communication',
    buttons=communication_buttons
)
###

software_buttons = [
    PluginMenuButton(
        link='plugins:d3c:software_add',
        title='Add',
        icon_class='mdi mdi-plus-thick',
        color=ButtonColorChoices.GREEN
    )
]

softwareItem = PluginMenuItem(
    link='plugins:d3c:software_list',
    link_text='Software',
    buttons=software_buttons
)

productrel_buttons = [
    PluginMenuButton(
        link='plugins:d3c:productrelationship_add',
        title='Add',
        icon_class='mdi mdi-plus-thick',
        color=ButtonColorChoices.GREEN
    ),
]

productrelItem = PluginMenuItem(
    link='plugins:d3c:productrelationship_list',
    link_text='ProductRelationship',
    buttons=productrel_buttons
)

xgenericuri_buttons = [
    PluginMenuButton(
        link='plugins:d3c:xgenericuri_add',
        title='Add',
        icon_class='mdi mdi-plus-thick',
        color=ButtonColorChoices.GREEN
    ),
]

xgenericuriItem = PluginMenuItem(
    link='plugins:d3c:xgenericuri_list',
    link_text='XGenericUri',
    buttons=xgenericuri_buttons
)

hash_buttons = [
    PluginMenuButton(
        link='plugins:d3c:hash_add',
        title='Add',
        icon_class='mdi mdi-plus-thick',
        color=ButtonColorChoices.GREEN
    ),
]

hashItem = PluginMenuItem(
    link='plugins:d3c:hash_list',
    link_text='Hash',
    buttons=hash_buttons
)

filehash_buttons = [
    PluginMenuButton(
        link='plugins:d3c:filehash_add',
        title='Add',
        icon_class='mdi mdi-plus-thick',
        color=ButtonColorChoices.GREEN
    ),
]

filehashItem = PluginMenuItem(
    link='plugins:d3c:filehash_list',
    link_text='FileHash',
    buttons=filehash_buttons
)

###
communication_finding_buttons = [
    PluginMenuButton(
        link='plugins:d3c:communicationfinding_add',
        title='Add',
        icon_class='mdi mdi-plus-thick',
        color=ButtonColorChoices.GREEN
    ),
    PluginMenuButton(
        link='plugins:d3c:communicationfinding_import',
        title='Bulk Add',
        icon_class='mdi mdi-upload',
        color=ButtonColorChoices.CYAN
    )
]

communicationFindingItem = PluginMenuItem(
    link='plugins:d3c:communicationfinding_list',
    link_text='CommunicationFinding',
    buttons=communication_finding_buttons
)
###

_menu_items_findings = (
    findingItem,
    communicationFindingItem
)

_menu_items_models = (
    communicationItem,
    softwareItem,
    productrelItem,
    xgenericuriItem,
    hashItem,
    filehashItem
)

#####


# menu = PluginMenu(
#     label='Netbox-Findings',
#     groups=(('Findings', _menu_items),),
# )


if plugin_settings.get("version"):
    version = plugin_settings.get("version")
else:
    version = ""

if plugin_settings.get("top_level_menu"):
    menu = PluginMenu(
        label="D3C",
        groups=(("Findings", _menu_items_findings), ("Models", _menu_items_models),),
        icon_class="mdi mdi-beta",
    )
else:
    menu_items = (findingItem, communicationFindingItem, communicationItem, softwareItem,
                  productrelItem, xgenericuriItem, hashItem, filehashItem)
