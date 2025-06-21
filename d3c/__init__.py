import os
from netbox.plugins import PluginConfig
from .populate import REPO

from django.core.signals import request_started


class NetBoxDDCConfig(PluginConfig):
    """
    Plugin config for the D3C-Plugin initiating the CustomFields and CustomFieldChoiceSets.
    """

    name = 'd3c'
    verbose_name = 'NetBox D3C'
    description = 'Manage Device Detection and Device Chrateriszation in NetBox'
    version = '0.9'
    base_url = 'd3c'
    min_version = '4.2'
    required_settings = []
    default_settings = {
          "top_level_menu": True,
          "version": "0.8"
    }

    def ready(self):
        """ Initializes the Plugin."""
        request_started.connect(init_custom_fields)

        return super().ready()


config = NetBoxDDCConfig


def init_custom_fields(sender, environ, **kwargs):
    from .models import Dummy

    admin, created = Dummy.objects.get_or_create()
    print(admin, " ", created)

    if created:
        work()

    request_started.disconnect(init_custom_fields)


def work():
    """
    Creating all CustomFields, CustomFieldChoiceSets and initialize the default Device Roles.

    Parameters:
    - created: bool, indicates whether the plugin is started for the first time
    """
    from core.models import ObjectType
    from dcim.models import Device, DeviceRole, DeviceType, Interface
    from extras.models import CustomField, CustomFieldChoiceSet
    from extras.choices import CustomFieldTypeChoices
    from .models import FILEHASH_ALGO

    try:
        #   Create the custom fields
        cf, created = CustomField.objects.update_or_create(
            name='safety',
            type=CustomFieldTypeChoices.TYPE_BOOLEAN,
            required=False)
        cf.object_types.set([ObjectType.objects.get_for_model(Device)])

        cf, created = CustomField.objects.update_or_create(
            name='inventory_number',
            type=CustomFieldTypeChoices.TYPE_TEXT,
            required=False)
        cf.object_types.set([ObjectType.objects.get_for_model(Device)])

        cf, created = CustomField.objects.update_or_create(
            name='year',
            type=CustomFieldTypeChoices.TYPE_TEXT,
            required=False)
        cf.object_types.set([ObjectType.objects.get_for_model(Device)])

        cf, created = CustomField.objects.update_or_create(
            name='device_family',
            label='Device Family',
            type=CustomFieldTypeChoices.TYPE_TEXT,
            required=True)
        cf.object_types.set([ObjectType.objects.get_for_model(DeviceType)])

        cf, created = CustomField.objects.update_or_create(
            name='hardware_name',
            type=CustomFieldTypeChoices.TYPE_TEXT,
            required=False)
        cf.object_types.set([ObjectType.objects.get_for_model(DeviceType)])

        cf, created = CustomField.objects.update_or_create(
            name='hardware_version',
            type=CustomFieldTypeChoices.TYPE_TEXT,
            required=False)
        cf.object_types.set([ObjectType.objects.get_for_model(DeviceType)])

        cf, created = CustomField.objects.update_or_create(
            name='model_number',
            type=CustomFieldTypeChoices.TYPE_TEXT,
            required=True)
        cf.object_types.set([ObjectType.objects.get_for_model(DeviceType)])

        cf, created = CustomField.objects.update_or_create(
            name='cpe',
            label='CPE',
            type=CustomFieldTypeChoices.TYPE_TEXT,
            required=False)
        cf.object_types.set([ObjectType.objects.get_for_model(DeviceType)])

        cf, created = CustomField.objects.update_or_create(
            name='device_description',
            label='Device Description',
            type=CustomFieldTypeChoices.TYPE_TEXT,
            required=False)
        cf.object_types.set([ObjectType.objects.get_for_model(DeviceType)])

        cf, created = CustomField.objects.update_or_create(
            name='secondary_roles',
            label='Secondary Roles',
            type=CustomFieldTypeChoices.TYPE_MULTIOBJECT,
            related_object_type=ObjectType.objects.get_for_model(DeviceRole),
            required=False)
        cf.object_types.set([ObjectType.objects.get_for_model(Device)])

        # is_router
        is_router_key = 'd3c_is_router choices'
        choice_sets = CustomFieldChoiceSet.objects.filter(name=is_router_key)
        if not choice_sets.exists():
            cs_interface, created = CustomFieldChoiceSet.objects.get_or_create(
                name=is_router_key,
                description='Router Interface?',
                extra_choices=(
                    ('unknown', 'Unknown'),
                    ('yes', 'Yes'),
                    ('no', 'No'),
                    ('maybe', 'Maybe'),
                ))

            cf, created = CustomField.objects.update_or_create(
                name='is_router',
                type=CustomFieldTypeChoices.TYPE_SELECT,
                required=False,
                choice_set=cs_interface)

            cf.object_types.set([ObjectType.objects.get_for_model(Interface)])

        # Exposure
        is_exposure_key = 'd3c_exposure choices'
        choice_sets = CustomFieldChoiceSet.objects.filter(name=is_exposure_key)
        if not choice_sets.exists():
            cs_exposure, created = CustomFieldChoiceSet.objects.get_or_create(
                name=is_exposure_key,
                description='Device accessible from zone with lower trust?',
                extra_choices=(
                    ('unknown', 'Unknown'),
                    ('small', 'Small'),
                    ('indirect', 'Indirect'),
                    ('direct', 'Direct'),
                ))

            description = ("Small: Highly isolated zone. "
                           "Direct: Directly accessible to/from a zone with lower trust. "
                           "Indirect: Other accessible devices are accessible to/from a zone with lower trust.")
            cf, created = CustomField.objects.update_or_create(
                name='exposure',
                description=description,
                type=CustomFieldTypeChoices.TYPE_SELECT,
                required=False,
                choice_set=cs_exposure)

            cf.object_types.set([ObjectType.objects.get_for_model(Device)])

            # is_router
            is_algo_key = 'd3c_filehash_algo'
            choice_sets = CustomFieldChoiceSet.objects.filter(name=is_algo_key)
            if not choice_sets.exists():
                cs_interface, created = CustomFieldChoiceSet.objects.get_or_create(
                    name=is_algo_key,
                    extra_choices=FILEHASH_ALGO)

        print('Finished init for CustomFields')

        absolute_path = os.path.dirname(__file__)
        repo = REPO(os.path.join(absolute_path, "data/repo"))
        repo.start()
    ###
    except Exception as e:
        print("Failed init")
