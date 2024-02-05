#!/usr/bin/python3
#
#####################################################
#
#  Projekt: BSI-507
#  NetBox DDDC Plugin
#  file: scripts.py
#
#####################################################

from django.utils.text import slugify
from django.core.exceptions import ObjectDoesNotExist

from dcim.choices import DeviceStatusChoices, SiteStatusChoices
from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site, Interface
from ipam.models import IPAddress, Service
from extras.scripts import *
from d3c.models import Finding, DeviceExtra, DDDCAdmin, Communication
from extras.models import Tag

mapping_table = {'source': 'ml-module',
                 'confidence': 'likelihood',
                 'manufacturer': 'vendor',
                 'device_role': 'deviceType',
                 'mac_address': 'mac-address',
                 'is_router': 'router-if',
                 'oui': 'oui',
                 'device_type': 'product'
}

def get_value(key, data):
    if key in mapping_table.keys():
        if mapping_table[key] in data.keys():
            return(data[mapping_table[key]])
        else:
            return (None)
    else:
        return(None)

def get_value_unknown(key, data):
    if key in data.keys():
        return(data[key])
    else:
        return ('unknown')


class ImportDevice(Script):

    class Meta:
        name = "Import Device"
        description = "Import a device object from Device Manager"
        field_order = []

    def create_or_update_device(self, data):
        
        new_tag, created = Tag.objects.get_or_create(name='NEW')
        approved_tag, created = Tag.objects.get_or_create(name='APPROVED')
        rejected_tag, created = Tag.objects.get_or_create(name='REJECTED')

        device_id_ip = False
        new_ip_addresses = []

        if 'communications' in data.keys():
            comm_rel = data['communications']
            source_ip = comm_rel['source_ip'] + "/24"
            target_ip = comm_rel['destination_ip'] + "/24"
            
            try:
                source = IPAddress.objects.get(address=source_ip)
                self.log_success(f"Found source_ip {source_ip} {source}")
                source_device_id = Interface.objects.get(id=source.assigned_object_id).device
                self.log_success(f"Found source_device {source_device_id}")
            except ObjectDoesNotExist:
                self.log_warning(f"source does not exist")
                return (None)
            
            try:
                target = IPAddress.objects.get(address=target_ip)
                self.log_success(f"Found target_ip {target_ip} {target}")
                target_device_id = Interface.objects.get(id=target.assigned_object_id).device
                self.log_success(f"Found target_device {target_device_id}")
            except ObjectDoesNotExist:
                self.log_warning(f"target does not exist")
                return (None)
            
            a_comm, created = Communication.objects.get_or_create(
                source_device=source_device_id,
                target_device=target_device_id,
                source_ip_addr=source,
                target_ip_addr=target,
                target_port=comm_rel['destination_port'],
                network_protocol=comm_rel['network_protocol'],
                transport_protocol=comm_rel['transport_protocol'].upper(),
                application_protocol=comm_rel['application_protocol'])
            a_comm.save()
            a_comm.tags.add("NEW")
            self.log_success(f"Created Communication {a_comm.id}")

            return(None)

        ##############
        
        if 'ipv4-services' in data.keys():
            for a_service in data['ipv4-services']:
                an_ip, created = IPAddress.objects.get_or_create(address=a_service['ip-addr'] + "/24")
                if not created:
                    device_id_ip = Interface.objects.get(id=an_ip.assigned_object_id).device
                else:
                    new_ip_addresses.append(an_ip)
                    an_ip.tags.add("NEW")
                    self.log_success(f"Created IP Address {a_service['ip-addr']}")

                        
        new_mac_addresses = []
        device_id_mac = False
        if 'mac-addresses' in data.keys():
            for a_mac_addr in data['mac-addresses']:
                try:
                    intf = Interface.objects.get(mac_address=a_mac_addr)
                    device_id_mac = Interface.objects.get(mac_address=a_mac_addr).device
                except ObjectDoesNotExist:
                    new_mac_addresses.append(a_mac_addr)

        if device_id_ip and device_id_mac and (device_id_ip != device_id_mac):
            device_id = False
            self.log_failure("Device Id inconsistent")
        elif device_id_ip and not device_id_mac:
            device_id = device_id_ip
        elif not device_id_ip and device_id_mac:
            device_id = device_id_mac
        else:
            device_id = device_id_ip

        if not device_id:
            new_device = Device(
                site=Site.objects.get(name='PoC'),
                device_type=DeviceType.objects.get(manufacturer=Manufacturer.objects.get(name='Unspecified'), model='Unspecified'),
                device_role=DeviceRole.objects.get(name='Unspecified')) 
            new_device.save()
            new_device.tags.add("NEW")
            device_id = new_device.id
            self.log_success(f"Created Device {device_id}")
        else:
            help = device_id.id
            device_id = help

        interface_number = 1
        for an_ip_address in new_ip_addresses:
            new_interface, created = Interface.objects.get_or_create(name="L3-Interface-" + str(interface_number), device_id=device_id, type="other")
            if created:
                new_interface.save()
                new_interface.tags.add("NEW")
                interface_number = interface_number + 1
                an_ip.assigned_object= new_interface
                an_ip.save()
                self.log_success(f"Created L3 Interface")

        interface_number = 1
        for a_mac_address in new_mac_addresses:
            new_interface, created = Interface.objects.get_or_create(name="L2-Interface-" + str(interface_number), device_id=device_id, mac_address=a_mac_address, type="other")
            if created:
                new_interface.save()
                new_interface.tags.add("NEW")
                interface_number = interface_number + 1
                self.log_success(f"Created L2 Interface {a_mac_address}")

        if 'ipv4-services' in data.keys():
            for a_service in data['ipv4-services']:
                an_ip = IPAddress.objects.get(address=a_service['ip-addr'] + "/24")
                if 'server' in a_service.keys():
                    for a_server in a_service['server']:
                        for a_serv in a_server['services']:
                            new_service, created = Service.objects.get_or_create(
                                device_id=device_id,
                                name=a_serv['application-protocol'],
                                protocol=a_server['transport-protocol'],
                                ports=[int(a_serv['port'])])
                            if created:
                                new_service.ipaddresses.add(an_ip)
                                new_service.save()
                                new_service.tags.add("NEW")
                                self.log_success(f"Created Service {a_server['transport-protocol']} {a_serv['port']}")

        if 'findings' in data.keys():
            for a_finding in data['findings']:
                new_find, created = Finding.objects.get_or_create(
                    device_id=device_id,
                    source=get_value('source', a_finding),
                    manufacturer=get_value('manufacturer', a_finding),
                    device_type=get_value('device_type', a_finding),
                    device_role=get_value('device_role', a_finding),
                    confidence=get_value('confidence', a_finding),
                    oui=get_value('oui', a_finding),
                    mac_address=get_value('mac_address', a_finding),
                    is_router=get_value('is_router', a_finding))
                if created:
                    new_find.save()
                    new_find.tags.add("NEW")
                    self.log_success(f"Created Finding")

        return (device_id)


    def run(self, data, commit):
        self.create_or_update_device(data)



