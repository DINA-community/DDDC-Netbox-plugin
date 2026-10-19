"""
Plugin initialization: create the custom fields and custom fields choice sets

This is called in post_migrate by Django
"""
import logging

from core.models import ObjectType
from dcim.models import Device, DeviceRole, DeviceType, Interface, ModuleType
from django.db.models.signals import post_migrate
from django.dispatch import receiver
from extras.choices import CustomFieldTypeChoices
from extras.models import CustomField, CustomFieldChoiceSet

from .models import FILEHASH_ALGO

logger = logging.getLogger('netbox.plugins.d3c')


@receiver(post_migrate)
def init_custom_fields(sender, **kwargs):
    if getattr(sender, 'name', None) != 'd3c':
        return

    checkFields()


def checkFields():
    """ Creating all CustomFields and CustomFieldChoiceSets. """
    #   Create the custom fields
    cf = CustomField.objects.update_or_create(
        name='safety',
        defaults={
            'type': CustomFieldTypeChoices.TYPE_BOOLEAN,
            'required': False
        })[0]
    cf.object_types.set([ObjectType.objects.get_for_model(Device)])

    cf = CustomField.objects.update_or_create(
        name='inventory_number',
        defaults={
            'type': CustomFieldTypeChoices.TYPE_TEXT,
            'required': False
        })[0]
    cf.object_types.set([ObjectType.objects.get_for_model(Device)])

    cf = CustomField.objects.update_or_create(
        name='year',
        defaults={
            'type': CustomFieldTypeChoices.TYPE_TEXT,
            'required': False
        })[0]
    cf.object_types.set([ObjectType.objects.get_for_model(Device)])

    # Device Type fields, in order of weight:
    # cpe 10
    # device_description 20
    # device_family 30
    # model_number 40
    # hardware_name 50
    # hardware_version 60
    cf = CustomField.objects.update_or_create(
        name='device_family',
        defaults={
            'label': 'Device Family',
            'type': CustomFieldTypeChoices.TYPE_TEXT,
            'required': True,
            'weight': 30,
        })[0]
    cf.object_types.set([ObjectType.objects.get_for_model(DeviceType)])

    cf = CustomField.objects.update_or_create(
        name='hardware_name',
        defaults={
            'description': 'Set to "-" when unknown.',
            'type': CustomFieldTypeChoices.TYPE_TEXT,
            'required': True,
            'weight': 50,
        })[0]
    cf.object_types.set([
        ObjectType.objects.get_for_model(DeviceType),
        ObjectType.objects.get_for_model(ModuleType)
        ])

    cf = CustomField.objects.update_or_create(
        name='hardware_version',
        defaults={
            'type': CustomFieldTypeChoices.TYPE_TEXT,
            'required': False,
            'weight': 60,
        })[0]
    cf.object_types.set([
        ObjectType.objects.get_for_model(DeviceType),
        ObjectType.objects.get_for_model(ModuleType)
        ])

    cf = CustomField.objects.update_or_create(
        name='model_number',
        defaults={
            'description': 'Set to "-" when unknown.',
            'type': CustomFieldTypeChoices.TYPE_TEXT,
            'required': True,
            'weight': 40,
        })[0]
    cf.object_types.set([
        ObjectType.objects.get_for_model(DeviceType),
        ObjectType.objects.get_for_model(ModuleType)
        ])

    cf = CustomField.objects.update_or_create(
        name='cpe',
        defaults={
            'label': 'CPE',
            'type': CustomFieldTypeChoices.TYPE_TEXT,
            'required': False,
            'weight': 10,
        })[0]
    cf.object_types.set([
        ObjectType.objects.get_for_model(DeviceType),
        ObjectType.objects.get_for_model(ModuleType)
        ])

    cf = CustomField.objects.update_or_create(
        name='device_description',
        defaults={
            'label': 'Device Description',
            'type': CustomFieldTypeChoices.TYPE_TEXT,
            'required': False,
            'weight': 20,
        })[0]
    cf.object_types.set([ObjectType.objects.get_for_model(DeviceType)])

    # ModuleType custom fields
    cf = CustomField.objects.update_or_create(
        name='module_family',
        defaults={
            'label': 'Module Family',
            'type': CustomFieldTypeChoices.TYPE_TEXT,
            'required': True,
            'weight': 30,
        })[0]
    cf.object_types.set([ObjectType.objects.get_for_model(ModuleType)])

    cf = CustomField.objects.update_or_create(
        name='secondary_roles',
        defaults={
            'label': 'Secondary Roles',
            'type': CustomFieldTypeChoices.TYPE_MULTIOBJECT,
            'related_object_type': ObjectType.objects.get_for_model(DeviceRole),
            'required': False
        })[0]
    cf.object_types.set([ObjectType.objects.get_for_model(Device)])

    # is_router
    cs_interface = CustomFieldChoiceSet.objects.get_or_create(
        name='d3c_is_router choices',
        defaults={
            'description': 'Router Interface?',
            'extra_choices': (
                ('unknown', 'Unknown'),
                ('yes', 'Yes'),
                ('no', 'No'),
                ('maybe', 'Maybe'),
            )
        })[0]
    cf = CustomField.objects.update_or_create(
        name='is_router',
        defaults={
            'type': CustomFieldTypeChoices.TYPE_SELECT,
            'required': False,
            'choice_set': cs_interface
        })[0]
    cf.object_types.set([ObjectType.objects.get_for_model(Interface)])

    # Exposure
    cs_exposure = CustomFieldChoiceSet.objects.get_or_create(
        name='d3c_exposure choices',
        defaults={
            'description': 'Device accessible from zone with lower trust?',
            'extra_choices': (
                ('unknown', 'Unknown'),
                ('small', 'Small'),
                ('indirect', 'Indirect'),
                ('direct', 'Direct'),
            )
        })[0]
    description = ("Small: Highly isolated zone. "
                   "Direct: Directly accessible to/from a zone with lower trust. "
                   "Indirect: Other accessible devices are accessible to/from a zone with lower trust.")
    cf = CustomField.objects.update_or_create(
        name='exposure',
        defaults={
            'description': description,
            'type': CustomFieldTypeChoices.TYPE_SELECT,
            'required': False,
            'choice_set': cs_exposure
        })[0]
    cf.object_types.set([ObjectType.objects.get_for_model(Device)])

    # File hash algorithms
    CustomFieldChoiceSet.objects.get_or_create(
        name='d3c_filehash_algo',
        defaults={'extra_choices': FILEHASH_ALGO})

    logger.info('Finished init for CustomFields')
