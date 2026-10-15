from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
from django.test import TestCase
from ipam.models import IPAddress, Service

from d3c.device_update import add_service


class AddSoftwareTestCase(TestCase):
    """TODO: add_software"""

    def test_placeholder(self):
        pass


class AddServiceTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        manufacturer = Manufacturer.objects.create(name='Manufacturer', slug='manufacturer')
        cls.device = Device.objects.create(
            name='Device',
            device_type=DeviceType.objects.create(manufacturer=manufacturer, model='Device Type', slug='device-type'),
            role=DeviceRole.objects.create(name='Role', slug='role'),
            site=Site.objects.create(name='Site', slug='site'),
        )

    def get_services(self):
        return Service.objects.filter(parent_object_id=self.device.pk)

    def test_create_service(self):
        self.assertEqual(add_service(self.device, None, 'ipv4', 'TCP', 'https', '443'), (True, None))
        service = self.get_services().get()
        self.assertEqual(service.parent, self.device)
        self.assertEqual(service.name, 'https')
        self.assertEqual(service.port_mappings, ['tcp/443'])

    def test_float_port(self):
        self.assertEqual(add_service(self.device, None, 'ipv4', 'udp', 'syslog', '514.0'), (True, None))
        self.assertEqual(self.get_services().get().port_mappings, ['udp/514'])

    def test_reuse_existing_service(self):
        add_service(self.device, None, 'ipv4', 'tcp', 'https', '443')
        self.assertEqual(add_service(self.device, None, 'ipv4', 'tcp', 'https', '443'), (True, None))
        self.assertEqual(self.get_services().count(), 1)

    def test_missing_application_protocol(self):
        add_service(self.device, None, 'ipv4', 'tcp', None, '443')
        self.assertEqual(self.get_services().get().name, 'Unspecified')

    def test_assign_ip_address(self):
        ip_address = IPAddress.objects.create(address='192.168.1.1/32')
        add_service(self.device, '192.168.1.1', 'ipv4', 'tcp', 'https', '443')
        self.assertEqual(list(self.get_services().get().ipaddresses.all()), [ip_address])

    def test_invalid_input(self):
        for transport_protocol, port in ((None, '443'), ('tcp', None), ('tcp', ''), ('tcp', 'http'), ('tcp', '514.5')):
            with self.subTest(transport_protocol=transport_protocol, port=port):
                success, error = add_service(self.device, None, 'ipv4', transport_protocol, 'https', port)
                self.assertFalse(success)
                self.assertTrue(error)
        self.assertFalse(self.get_services().exists())


class FindInterfaceTestCase(TestCase):
    """TODO: find_interface"""

    def test_placeholder(self):
        pass


class CreateAndAssignInterfaceTestCase(TestCase):
    """TODO: create_and_assign_interface"""

    def test_placeholder(self):
        pass


class ChangeDeviceTypeTestCase(TestCase):
    """TODO: change_manufacturer_of_device_type, change_device_type_keep_manufacturer, change_device_type_and_manufacturer"""

    def test_placeholder(self):
        pass


class SiteGetOrCreateTestCase(TestCase):
    """TODO: site_get_or_create"""

    def test_placeholder(self):
        pass


class ChangeDeviceRackLocationTestCase(TestCase):
    """TODO: change_device_rack, change_device_location"""

    def test_placeholder(self):
        pass


class ChangeDeviceFieldsTestCase(TestCase):
    """TODO: change_device_role, change_device_site, change_device_status, change_device_exposure, change_device_safety, change_device_router, change_device_hver, change_device_hcpe, change_device_name, change_device_family, change_device_description, change_device_model_number, change_device_serial_number"""

    def test_placeholder(self):
        pass


class IsMacEqualTestCase(TestCase):
    """TODO: is_mac_equal"""

    def test_placeholder(self):
        pass
