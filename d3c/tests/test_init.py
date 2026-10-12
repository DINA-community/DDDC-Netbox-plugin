from django.test import TestCase

from core.models import ObjectType
from dcim.models import Device, DeviceType, Interface, ModuleType
from extras.models import CustomField, CustomFieldChoiceSet

from d3c.signals import checkFields

# Custom fields, mapped to the model
EXPECTED_FIELDS = {
    'safety': [Device],
    'inventory_number': [Device],
    'year': [Device],
    'device_family': [DeviceType],
    'hardware_name': [DeviceType, ModuleType],
    'hardware_version': [DeviceType, ModuleType],
    'model_number': [DeviceType, ModuleType],
    'cpe': [DeviceType, ModuleType],
    'device_description': [DeviceType],
    'module_family': [ModuleType],
    'secondary_roles': [Device],
    'is_router': [Interface],
    'exposure': [Device],
}

EXPECTED_CHOICE_SETS = {
    'd3c_is_router choices',
    'd3c_exposure choices',
    'd3c_filehash_algo',
}

# Custom fields that are required
EXPECTED_REQUIRED = {'device_family', 'hardware_name', 'model_number', 'module_family'}


class CheckFieldsTestCase(TestCase):
    def test_creates_expected_fields(self):
        for name, models in EXPECTED_FIELDS.items():
            with self.subTest(field=name):
                cf = CustomField.objects.get(name=name)
                self.assertEqual(
                    set(cf.object_types.values_list('pk', flat=True)),
                    {ObjectType.objects.get_for_model(m).pk for m in models},
                )

    def test_creates_expected_choice_sets(self):
        names = set(CustomFieldChoiceSet.objects.filter(
            name__in=EXPECTED_CHOICE_SETS).values_list('name', flat=True))
        self.assertEqual(names, EXPECTED_CHOICE_SETS)

    def test_required_fields(self):
        required = set(CustomField.objects.filter(
            name__in=EXPECTED_FIELDS, required=True).values_list('name', flat=True))
        self.assertEqual(required, EXPECTED_REQUIRED)

    def test_is_idempotent(self):
        before = CustomField.objects.filter(name__in=EXPECTED_FIELDS).count()
        choice_sets_before = CustomFieldChoiceSet.objects.filter(
            name__in=EXPECTED_CHOICE_SETS).count()

        checkFields()
        checkFields()

        self.assertEqual(CustomField.objects.filter(name__in=EXPECTED_FIELDS).count(),
                         before)
        self.assertEqual(CustomFieldChoiceSet.objects.filter(name__in=EXPECTED_CHOICE_SETS).count(),
                         choice_sets_before)

    def test_repairs_a_deleted_field(self):
        CustomField.objects.filter(name='device_family').delete()

        checkFields()

        cf = CustomField.objects.get(name='device_family')
        self.assertTrue(cf.required)
        self.assertEqual(
            set(cf.object_types.values_list('pk', flat=True)),
            {ObjectType.objects.get_for_model(DeviceType).pk},
        )
