from netbox.plugins import PluginConfig


class NetBoxDDCConfig(PluginConfig):
    """
    Plugin config for the D3C-Plugin initiating the CustomFields and CustomFieldChoiceSets.
    """

    name = 'd3c'
    verbose_name = 'NetBox D3C'
    description = 'Manage Device Detection and Device Chrateriszation in NetBox'
    version = '0.9'
    base_url = 'd3c'
    min_version = '4.7'
    required_settings = []
    default_settings = {
          "top_level_menu": True,
          "version": "0.8"
    }

    def ready(self):
        """ Initializes the Plugin."""
        from . import signals

        return super().ready()


config = NetBoxDDCConfig
