"""
    This file provides functionalities for editing a device based on new values provided by a DeviceFinding.
"""

from typing import Optional

from dcim.models import Interface, Manufacturer, DeviceType, DeviceRole, Site, Rack, Location, Device, MACAddress
from django.db.models import Q
from django.utils.text import slugify
from ipam.models import IPAddress, Service
from .utils import get_ip, parse_ip
from .string_helper import check_choice
from dcim.choices import DeviceStatusChoices
from extras.models import CustomFieldChoiceSet
from .models import Software, ProductRelationship, ProductRelationshipCategory
from django.contrib.contenttypes.models import ContentType


def get_current_value_for_device(device, findingfield):
    """
    This function returns the corresponding Device value based on a DeviceFinding attribute.
    """
    if not device:
        return None
    ff = findingfield.lower()

    # Mapping of field names to extraction functions
    field_map = {
        'manufacturer': lambda d: d.device_type.manufacturer.name,
        'device_role': lambda d: d.role,
        'device_type': lambda d: d.device_type,
        'device_name': lambda d: d.name,
        'device_family': lambda d: d.device_type.custom_field_data.get('device_family'),
        'description': lambda d: d.device_type.description,
        'article_number': lambda d: d.device_type.custom_field_data.get('article_number'),
        'part_number': lambda d: d.device_type.part_number,
        'serial_number': lambda d: d.serial,
        'status': lambda d: d.status,
        'exposure': lambda d: d.custom_field_data.get('exposure'),
        'site': lambda d: d.site,
        'rack': lambda d: d.rack,
        'location': lambda d: d.location,
        'is_safety_critical': lambda d: d.custom_field_data.get('safety'),
        'hardware_version': lambda d: d.device_type.custom_field_data.get('hardware_version'),
        'hardware_cpe': lambda d: d.device_type.custom_field_data.get('cpe'),
    }
    # Get the value using the field map
    extractor = field_map.get(ff)
    if extractor:
        try:
            value = extractor(device)
            return str(value) if value is not None else None
        except AttributeError:
            return None
        
    # Return original field name if not found
    return findingfield


def create_and_assign_interface(device: Device, interface_name: str,
                                ip_address: Optional[str] = None,
                                mac_address: Optional[str] = None):
    """
    This function creates a new Interface for a given device (object, required)
    with the provided interface name (string), IP address (string, optional),
    and MAC address (string, optional).
    """
    interface = Interface.objects.create(name=interface_name, device=device, type="other")

    if ip_address:
        ipaddr = IPAddress(address=ip_address, assigned_object=interface)
        #### TODO
        ipaddr.save()

    if mac_address:
        macaddr = MACAddress.objects.create(mac_address=mac_address, assigned_object=interface)
        interface.primary_mac_address = macaddr
        macaddr.save()

    interface.save()


def change_manufacturer_of_device_type(device, value):
    """
    This function updates the manufacturer value for a device.
    """
    if value and device and device.device_type and device.device_type.model:

        manufacturers = Manufacturer.objects.filter(Q(name=value) | Q(slug=slugify(value)))

        if manufacturers.exists():
            manufacturer = manufacturers[0]
        else:
            manufacturer = Manufacturer.objects.create(name=value, slug=slugify(value))

        if device.device_type.model == 'Unspecified':  # Create new Device Type
            device.device_type, _ = DeviceType.objects.get_or_create(manufacturer=manufacturer,
                                                                     model='Unspecified',
                                                                     slug=slugify(value))
            device.save()
        else:
            dt_model = device.device_type.model
            device_types = DeviceType.objects.filter(Q(model=dt_model) |
                                                     Q(slug=slugify(dt_model))).filter(manufacturer=manufacturer)
            if device_types.exists() and device_types[0].manufacturer.name == value:
                device.device_type = device_types[0]
                device.save()
            else:
                device.device_type, _ = DeviceType.objects.get_or_create(manufacturer=manufacturer,
                                                                         model=device.device_type.model,
                                                                         slug=slugify(device.device_type.model))
                device.device_type.save()

        return True
    else:
        return False


def change_device_type_keep_manufacturer(device, value):
    """
    This function updates the device type of a device while keeping the manufacturer.
    """
    ### revision in branch P625
    if device and device.device_type and value:

        device_types = DeviceType.objects.filter(Q(model=value) | Q(slug=slugify(value)))

        if device_types.exists() and device_types[0].pk == device.device_type.pk:
            return False  # Device Type already assigned

        old_manufacturer = device.device_type.manufacturer
        device.device_type, _ = DeviceType.objects.get_or_create(manufacturer=old_manufacturer,
                                                                 model=value,
                                                                 slug=slugify(value))
        device.save()
        return True
    else:
        return False


def change_device_type_and_manufacturer(device, device_type_value, manufacturer_value):
    """
    This function updates the device type and manufacturer of a device.
    """
    if device and device_type_value and manufacturer_value:
        manufacturers = Manufacturer.objects.filter(Q(name=manufacturer_value) | Q(slug=slugify(manufacturer_value)))
        if manufacturers.exists():
            manufacturer = manufacturers[0]
        else:
            manufacturer = Manufacturer.objects.create(name=manufacturer_value, slug=slugify(manufacturer_value))

        device.device_type, _ = DeviceType.objects.get_or_create(manufacturer=manufacturer,
                                                                 model=device_type_value,
                                                                 slug=slugify(device_type_value))
        device.save()
        return True
    else:
        return False


def change_device_role(device, value):
    """
    This function updates the Device Role of a device.
    """
    ### Need revision for handling child parents properly. Issue #1 
    if device and value:
        roles = DeviceRole.objects.filter(Q(name=value) | Q(slug=slugify(value)))
        if roles.exists():
            role = roles[0]
        else:
            role, _ = DeviceRole.objects.get_or_create(name=value, slug=slugify(value))

        if device.role and device.role.pk != role.pk:
            device.role = role
            device.save()
        return True

    return False


def site_get_or_create(value):
    """
    This function returns the Site based on the provided value.
    """
    sites = Site.objects.filter(Q(name=value) | Q(slug=slugify(value)))
    if sites.exists():
        site = sites[0]
    else:
        site, _ = Site.objects.get_or_create(name=value, slug=slugify(value))
    return site


def change_device_site(device, value):
    """
    This function updates the Site of a device.
    """
    if device and value:
        site = site_get_or_create(value)
        device.site = site
        device.save()
        return True

    return False


def change_device_rack(device, value, site):
    """
    This function updates the Rack of a device based on the Site.
    """
    if device and value and site:
        racks = Rack.objects.filter(Q(name=value))
        if racks.exists():
            rack = racks[0]
        else:
            site = site_get_or_create(value)
            rack, _ = Rack.objects.get_or_create(name=value, site=site)

        device.rack = rack
        device.save()
        return True

    return False


def change_device_location(device, value, site):
    """
    This function updates the Location of a device based on the provided Site.
    """
    if device and value and site:
        locations = Location.objects.filter(Q(name=value) | Q(slug=slugify(value)))
        if locations.exists():
            location = locations[0]
        else:
            site = site_get_or_create(value)
            location, _ = Location.objects.get_or_create(name=value, site=site)

        device.location = location
        device.save()
        return True

    return False


def change_device_status(device, value):
    """
   This function assigns the status value to a device.
    """
    if device and value:
        status = check_choice(DeviceStatusChoices.CHOICES, value)
        if status:
            device.status = status
            device.save()
            return True
        else:
            return False


def change_device_exposure(device, value):
    """
   This function assigns the exposure value to a device.
    """
    if device and value:
        try:
            choices = CustomFieldChoiceSet.objects.get(name='d3c_exposure choices').choices
            exposure = check_choice(choices, value)
            if exposure:
                device.custom_field_data['exposure'] = exposure
                device.save()
                return True
            else:
                return False
        except Exception:
            return False


def change_device_safety(device, value):
    """
   This function assigns the safety value to a device.
    """
    if device and value:
        device.custom_field_data['safety'] = value == "True"
        device.save()
        return True

    return False


def change_device_router(device, mac, ip, value):
    """
    This function assigns the is_router value to a device.
    """
    ### deprecated because roles can have child/parents #1
    if device and value and (ip or mac):
        interface = find_interface(device, mac, ip)
        if interface:
            val = 'yes' if value == "Yes" else "no"
            interface.custom_field_data['is_router'] = val
            interface.save()
            return True
        return False

    return False


def change_device_hver(device, value):
    """
    This function assigns a hardware version to a device.
    """
    if device and value:
        device.device_type.custom_field_data['hardware_version'] = value
        device.device_type.save()
        return True
    return False


def change_device_hcpe(device, value):
    """
    This function assigns a CPE value to a device.
    """
    if device and value:
        device.device_type.custom_field_data['cpe'] = value
        device.device_type.save()
        return True
    return False


def change_device_name(device, value):
    """
    This function assigns a name to a device.
    """
    if device and value:
        device.name = value
        device.save()
        return True
    return False


def change_device_family(device, value):
    """
    This function assigns the device_Family value to a device.
    """
    if device and value:
        device.device_type.custom_field_data['device_family'] = value
        device.device_type.save()
        return True
    return False


def change_device_description(device, value):
    """
    This function assigns a description to a device.
    """
    # necessary since it is core field? check in data model revision
    if device and value:
        device.device_type.description = value
        device.device_type.save()
        return True
    return False


def change_device_article_number(device, value):
    """
    This function assigns an article number to a device.
    """
    # Change in P625 into part_number
    if device and value:
        device.device_type.custom_field_data['article_number'] = value
        device.device_type.save()
        return True
    return False


def change_device_model_number(device, value):
    """
    This function assigns a model number to a device.
    """
    if device and value:
        device.device_type.part_number = value
        device.device_type.save()
        return True
    return False


def change_device_serial_number(device, value):
    """
    This function assigns a serial number to a device.
    """
    if device and value:
        device.serial = value
        device.save()
        return True
    return False


def is_mac_equal(mac_1, mac_2):
    """
    This function checks if two MAC addresses are equal.
    """
    return mac_1.lower() == mac_2.lower()


# def find_interface(device, mac, ip_address):
#     if device and (mac or ip_address):
#         for interface in device.vc_interfaces():
#             if mac and not ip_address:
#                 if is_mac_equal(mac, interface.mac_address.lower()):
#                     return interface
#             else:
#                 for interface_ip in interface.ip_addresses.all():
#                     if ip_address == str(interface_ip.address.ip):
#                         if not mac or is_mac_equal(mac, str(interface.mac_address)):
#                             return interface
#     return None

def find_interface(device, mac, ip):
    """
    This function performs a lookup based on the MAC and IP address
    to check if the device has a corresponding interface.
    """
    # TODO
    parsed_ip = None

    if ip:
        parsed_ip = parse_ip(ip)

    if device and (mac or parsed_ip):
        for interface in device.vc_interfaces():
            if mac and is_mac_equal(mac, str(interface.mac_address)):
                return interface

            if parsed_ip:
                for interface_ip in interface.ip_addresses.all():
                    if parsed_ip.prefixlen == 32:
                        if parsed_ip.ip == interface_ip.address.ip:
                            return interface
                    elif parsed_ip == interface_ip.address:
                        return interface
    return None


def add_service(device, ip_address, ip_netmask, network_protocol, transport_protocol, application_protocol, port):
    """
    This function creates a new Service object.
    """
    # network protocol and result unused, check by data model revision

    if not application_protocol or application_protocol == 'False':
        application_protocol = 'Unspecified'

    try:
        service, created = Service.objects.get_or_create(device=device,
                                                         name=application_protocol,
                                                         protocol=transport_protocol,
                                                         ports=[int(port)])
        ip = get_ip(ip_address, ip_netmask)
        if ip and created:
            ips = IPAddress.objects.filter(address=ip)
            if ips.exists():
                an_ip = IPAddress.objects.get(address=ip)
                service.ipaddresses.add(an_ip)
                service.save()
        return True
    except Exception as e:
        return False


def add_software(device, name, firmware, version):
    """
    This function creates a new Software object.
    """
    result = True

    name = name if name else 'Unspecified'
    version = version if version else 'Unspecified'
    firmware = firmware == "True"
# break
    software, created = Software.objects.get_or_create(name=name, is_firmware=firmware, version=version)

    try:
        relation, created = ProductRelationship.objects.get_or_create(source_type=ContentType.objects.get_for_model(Software),
                                                                      source_id=software.pk,
                                                                      category=ProductRelationshipCategory.INSTALLED_ON,
                                                                      destination_type=ContentType.objects.get_for_model(Device),
                                                                      destination_id=device.pk)
    except Exception as e:
        result = False
    finally:
        return result

