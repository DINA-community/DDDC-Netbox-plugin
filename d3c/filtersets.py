from netbox.filtersets import NetBoxModelFilterSet
from .models import DeviceFinding, Software, Communication, CommunicationFinding, Mapping
from django.db.models import Q


class DeviceFindingFilterSet(NetBoxModelFilterSet):
    """
    Definition of the Filterset for DeviceFindings.
    """
    class Meta:
        model = DeviceFinding
        fields = ('id', 'device', 'source', 'confidence',
                  'description', 'device_role', 'serial_number', 'device_name', 'status', 'site', 'rack', 'location',
                  'device_type', 'serial_number', 'device_role', 'is_safety_critical',
                  'ip_address', 'ip_netmask', 'mac_address', 'transport_protocol', 'application_protocol', 'port',
                  'is_router', 'manufacturer', 'oui', 'device_family', 'article_number', 'part_number',
                  'hardware_version', 'hardware_cpe', 'software_name', 'is_firmware', 'version',
                  'exposure', 'has_predicted_device', 'predicted_device')

    def search(self, queryset, name, value):
        """
        This method is executed when the QuickSearch input field is used.
        """
        if not value.strip():
            return queryset

        if value == "True" or value == "False":
            val = True if value == "True" else False
            return queryset.filter(has_predicted_device=val)
        else:
            return queryset.filter(Q(device_type__icontains=value) |
                                   Q(manufacturer__icontains=value) |
                                   Q(ip_address__icontains=value) |
                                   Q(mac_address__icontains=value) |
                                   Q(source__icontains=value))


class SoftwareFilterSet(NetBoxModelFilterSet):
    """
    Definition of the Filterset for Software.
    """
    class Meta:
        model = Software
        fields = ('id', 'name', 'is_firmware', 'version', 'cpe', 'purl')

    def search(self, queryset, name, value):
        return queryset.filter(name__icontains=value)


class CommunicationFilterSet(NetBoxModelFilterSet):
    """
    Definition of the Filterset for Communication.
    """
    class Meta:
        model = Communication
        fields = ('id', 'source_device', 'destination_device', 'source_ip_addr', 'destination_ip_addr', 'destination_port',
                  'network_protocol', 'transport_protocol', 'application_protocol')

    def search(self, queryset, name, value):
        return queryset.filter(description__icontains=value)


class CommunicationFindingFilterSet(NetBoxModelFilterSet):
    """
    Definition of the Filterset for CommunicationFinding.
    """
    class Meta:
        model = CommunicationFinding
        fields = ('id', 'source_ip', 'destination_ip', 'destination_port', 'network_protocol', 'transport_protocol',
                  'application_protocol', 'predicted_src_device', 'predicted_dst_device', 'has_2_predicted_devices')

    def search(self, queryset, name, value):
        return queryset.filter(description__icontains=value)


class MappingFilterSet(NetBoxModelFilterSet):
    """
    Definition of the Filterset for Mapping.
    """
    class Meta:
        model = Mapping
        fields = ('id', 'type', 'name')

    def search(self, queryset, name, value):
        return queryset.filter(name__icontains=value)
