from django.contrib.messages import ERROR, get_messages
from django.urls import reverse
from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site, Platform
from ipam.models import Service
from utilities.testing import ModelViewTestCase, TestCase, create_tags

from d3c import models


class DeviceFindingMapTestCase(ModelViewTestCase):
    """TODO: DeviceFindingMap"""
    model = models.DeviceFinding

    def test_placeholder(self):
        pass


class DeviceFindingRejectTestCase(ModelViewTestCase):
    """TODO: DeviceFindingReject"""
    model = models.DeviceFinding

    def test_placeholder(self):
        pass


class DeviceFindingSplitTestCase(ModelViewTestCase):
    """TODO: DeviceFindingSplit"""
    model = models.DeviceFinding

    def test_placeholder(self):
        pass


class DeviceFindingApplyTestCase(ModelViewTestCase):
    """TODO: DeviceFindingApply"""
    model = models.DeviceFinding

    def test_placeholder(self):
        pass


class DeviceFindingLookupViewTestCase(ModelViewTestCase):
    """TODO: DeviceFindingLookupView"""
    model = models.DeviceFinding

    def test_placeholder(self):
        pass


class CommunicationFindingMapTestCase(ModelViewTestCase):
    """TODO: CommunicationFindingMap"""
    model = models.CommunicationFinding

    def test_placeholder(self):
        pass


class CommunicationFindingRejectTestCase(ModelViewTestCase):
    """TODO: CommunicationFindingReject"""
    model = models.CommunicationFinding

    def test_placeholder(self):
        pass


class FindingListForDeviceViewTestCase(TestCase):
    """Applying the service of a finding via the Findings tab of a device."""

    @classmethod
    def setUpTestData(cls):
        manufacturer = Manufacturer.objects.create(name='Manufacturer', slug='manufacturer')
        cls.device = Device.objects.create(
            name='Device',
            device_type=DeviceType.objects.create(
                manufacturer=manufacturer, model='Device Type', slug='device-type'),
            role=DeviceRole.objects.create(name='Role', slug='role'),
            site=Site.objects.create(name='Site', slug='site'),
        )
        cls.finding = models.DeviceFinding.objects.create(source='manual', device=cls.device)

    def apply_service(self, port):
        finding_id = self.finding.pk
        return self.client.post(
            reverse('dcim:device_findinglistfordeviceview', kwargs={'pk': self.device.pk}), {
            f'id-{finding_id}': 'on',
            f'service-{finding_id}': 'on',
            f'ip_address-{finding_id}': '192.168.1.1',
            f'network_protocol-{finding_id}': 'ipv4',
            f'transport_protocol-{finding_id}': 'udp',
            f'application_protocol-{finding_id}': 'syslog',
            f'port-{finding_id}': port,
        })

    def test_port_as_decimal_number(self):
        response = self.apply_service('514.0')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Service.objects.get(parent_object_id=self.device.pk).port_mappings, ['udp/514'])

    def test_invalid_port_shows_error(self):
        response = self.apply_service('http')
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Service.objects.filter(parent_object_id=self.device.pk).exists())
        errors = [str(m) for m in get_messages(response.wsgi_request) if m.level == ERROR]
        self.assertTrue(any('Port must be an integer' in e for e in errors), errors)


class DeviceTypeEditViewTestCase(ModelViewTestCase):
    """
    d3c replaces NetBox's DeviceTypeEditView and
    NetBox's own unittests can't be used as they don't know of the Custom Fields.
    """
    model = DeviceType

    @classmethod
    def setUpTestData(cls):
        cls.manufacturer = Manufacturer.objects.create(
            name='Manufacturer 1', slug='manufacturer-1')
        cls.platform = Platform.objects.create(name='Platform 1', slug='platform-1')
        cls.tags = create_tags('Alpha', 'Bravo')

    def _post_data(self, **overrides):
        data = {
            'manufacturer': self.manufacturer.pk,
            'cf_device_family': 'DeviceFamily',
            'cf_model_number': 'ModelNumber 1',
            'cf_hardware_name': 'HardwareNumber 1',
        }
        data.update(overrides)
        return data

    def test_create_requires_manufacturer(self):
        self.add_permissions('dcim.add_devicetype')
        data = self._post_data()
        del data['manufacturer']

        response = self.client.post(reverse('dcim:devicetype_add'), data)
        # FIXME check error message

        self.assertHttpStatus(response, 200)
        self.assertFalse(DeviceType.objects.exists())

    def test_create_requires_device_family(self):
        self.add_permissions('dcim.add_devicetype')

        response = self.client.post(reverse('dcim:devicetype_add'), self._post_data(cf_device_family=''))

        self.assertHttpStatus(response, 200)
        self.assertFalse(DeviceType.objects.exists())

    def test_create_only_required(self):
        """ Create a Device Type with only the required fields. """
        self.add_permissions('dcim.add_devicetype')

        response = self.client.post(reverse('dcim:devicetype_add'), self._post_data())

        self.assertHttpStatus(response, 302)
        device_type = DeviceType.objects.get()
        self.assertEqual(device_type.manufacturer, self.manufacturer)
        self.assertEqual(device_type.custom_field_data['device_family'], 'DeviceFamily')

    def test_model_custom_slug(self):
        self.add_permissions('dcim.add_devicetype')

        self.client.post(reverse('dcim:devicetype_add'),
                         self._post_data(cf_hardware_version='1.2', part_number='PN-9'))

        device_type = DeviceType.objects.get()
        self.assertEqual(device_type.model,
                         'DeviceFamily ModelNumber 1 HardwareNumber 1 1.2 PN-9')


class SoftwareTypeViewTestCase(ModelViewTestCase):
    """
    Tests SoftwareType views
    """
    model = models.SoftwareType

    @classmethod
    def setUpTestData(cls):
        cls.manufacturer = Manufacturer.objects.create(
            name='Manufacturer 2', slug='manufacturer-2')
        cls.tags = create_tags('Alpha', 'Bravo')

    def _post_data(self, **overrides):
        data = {
            'manufacturer': self.manufacturer.pk,
            'name': 'TSoftwareType1'
        }
        data.update(overrides)
        return data

    def test_add_a_software_type(self):
        self.add_permissions('d3c.add_softwaretype', 'dcim.view_manufacturer')
        data = self._post_data()
        response = self.client.post(reverse('plugins:d3c:softwaretype_add'), data)
        self.assertHttpStatus(response, 302)
        self.assertTrue(models.SoftwareType.objects.exists())

    def test_delete_a_software_type(self):
        self.add_permissions('d3c.delete_softwaretype')
        software_type = models.SoftwareType.objects.create(
            name='Test', manufacturer=self.manufacturer)
        data = {'pk': software_type.pk}
        response = self.client.post(
            reverse('plugins:d3c:softwaretype_delete', kwargs=data), {'confirm': 'True'})
        self.assertHttpStatus(response, 302)
        self.assertFalse(
            models.SoftwareType.objects.filter(pk=data['pk']))

    def test_look_at_a_software_type(self):
        self.add_permissions('d3c.view_softwaretype')
        software_type_name = 'TSoftwareTypeA'
        software_type = models.SoftwareType.objects.create(
            name=software_type_name, manufacturer=self.manufacturer)
        data = {'pk': software_type.pk}
        response = self.client.get(reverse('plugins:d3c:softwaretype', kwargs=data))
        self.assertHttpStatus(response, 200)
        self.assertTrue(software_type_name in str(response.content))

    def test_list_software_types(self):
        self.add_permissions('d3c.view_softwaretype')
        names = ('SoftwareTypeA', 'SoftwareTypeB', 'SoftwareTypeC')
        for name in names:
            models.SoftwareType.objects.create(name=name, manufacturer=self.manufacturer)
        response = self.client.get(reverse('plugins:d3c:softwaretype_list'))
        self.assertHttpStatus(response, 200)
        for name in names:
            self.assertIn(name, str(response.content))

    def test_edit_a_software_type(self):
        self.add_permissions('d3c.change_softwaretype', 'd3c.view_softwaretype', 'dcim.view_manufacturer')
        softwaretype = models.SoftwareType.objects.create(
            name='TSoftwareTypeA', manufacturer=self.manufacturer)
        pk = softwaretype.pk
        response = self.client.post(
            reverse('plugins:d3c:softwaretype_edit', kwargs={'pk': pk}),
            {'name': 'SoftwareTypeAplus', 'confirm': 'True', 'manufacturer': self.manufacturer.pk}
        )
        self.assertHttpStatus(response, 302)
        self.assertEqual(
            models.SoftwareType.objects.get(pk=pk).name, 'SoftwareTypeAplus'
        )


class SoftwareViewTestCase(ModelViewTestCase):
    """
    Tests Software views
    """
    model = models.Software

    @classmethod
    def setUpTestData(cls):
        cls.manufacturer = Manufacturer.objects.create(
            name='Manufacturer 3', slug='manufacturer-3')
        cls.software_type = models.SoftwareType.objects.create(
            name='Software Type 1', manufacturer=cls.manufacturer
        )
        cls.tags = create_tags('Alpha', 'Bravo')

    def _post_data(self, **overrides):
        data = {
            'software_type': self.software_type.pk,
            'name': 'TSoftware1'
        }
        data.update(overrides)
        return data

    def test_add_a_software(self):
        self.add_permissions('d3c.add_software', 'd3c.view_softwaretype')
        data = self._post_data()
        response = self.client.post(reverse('plugins:d3c:software_add'), data)
        self.assertHttpStatus(response, 302)
        self.assertTrue(models.SoftwareType.objects.exists())

    def test_delete_a_software(self):
        self.add_permissions('d3c.delete_software')
        software = models.Software.objects.create(
            name='TSoftware1', software_type=self.software_type
        )
        pk = software.pk
        response = self.client.post(
            reverse('plugins:d3c:software_delete', kwargs={'pk': pk}), {'confirm': 'True'}
        )
        self.assertHttpStatus(response, 302)
        self.assertFalse(models.Software.objects.filter(pk=pk))

    def test_look_at_a_software(self):
        software_name = 'TestSoftwareA'
        self.add_permissions('d3c.view_software')
        software = models.Software.objects.create(
            name=software_name, software_type=self.software_type)
        data = {'pk': software.pk}
        response = self.client.get(reverse('plugins:d3c:software', kwargs=data))
        self.assertHttpStatus(response, 200)
        self.assertIn(software_name, str(response.content))

    def test_list_softwares(self):
        names = ('SoftwareA', 'SoftwareB', 'SoftwareC')
        self.add_permissions('d3c.view_software')
        for name in names:
            models.Software.objects.create(name=name, software_type=self.software_type)
        response = self.client.get(reverse('plugins:d3c:software_list'))
        self.assertHttpStatus(response, 200)
        for name in names:
            self.assertIn(name, str(response.content))

    def test_edit_a_software(self):
        self.add_permissions('d3c.change_software', 'd3c.view_software', 'd3c.view_softwaretype')
        software = models.Software.objects.create(
            name='TSoftwareA', software_type=self.software_type)
        pk = software.pk
        response = self.client.post(
            reverse('plugins:d3c:software_edit', kwargs={'pk': pk}),
            {'name': 'TSoftwareAplus', 'software_type': self.software_type.pk, 'confirm': 'True'}
        )
        self.assertHttpStatus(response, 302)
        self.assertEqual(
            models.Software.objects.get(pk=pk).name, 'TSoftwareAplus'
        )
