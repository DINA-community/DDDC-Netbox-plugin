import django_filters
from django.db.models import Q
from netbox.filtersets import NetBoxModelFilterSet
from dcim.models import Manufacturer
from .models import DeviceFinding, Software, Communication, CommunicationFinding, Mapping, ProductRelationship, XGenericUri, Hash, FileHash


class DeviceFindingFilterSet(NetBoxModelFilterSet):
    """
    Definition of the Filterset for DeviceFindings.
    """
    class Meta:
        model = DeviceFinding
        fields = ('id', 'device', 'source', 'confidence',
                  'description', 'device_role', 'serial_number', 'device_name', 'status', 'site', 'rack', 'location',
                  'device_type', 'serial_number', 'device_role', 'is_safety_critical',
                  'ip_address', 'mac_address', 'transport_protocol', 'application_protocol', 'port',
                  'is_router', 'manufacturer', 'oui', 'device_family', 'part_number',
                  'hardware_version', 'hardware_cpe', 'software_name', 'is_firmware', 'version',
                  'exposure', 'has_predicted_device', 'predicted_device')

    def search(self, queryset, name, value):
        """
        This method is excecuted when the QuickSearch input field is used.
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
    manufacturer_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Manufacturer.objects.all(),
        label='Manufacturer (ID)',
    )
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

class ProductRelationshipFilterSet(NetBoxModelFilterSet):
    """
    Definition of the Filterset for ProductRelationship.
    """
    class Meta:
        model = ProductRelationship
        fields = (
            'id', 'source_type', 'source_id', 'category', 'destination_type', 'destination_id')

    def search(self, queryset, name, value):
        return queryset.filter(description__icontains=value)

class XGenericUriFilterSet(NetBoxModelFilterSet):
    """
    Definition of the Filterset for XGenericUri.
    """
    class Meta:
        model = XGenericUri
        fields = (
            'id', 'content_type', 'object_id', 'namespace')

    def search(self, queryset, name, value):
        return queryset.filter(description__icontains=value)

class HashFilterSet(NetBoxModelFilterSet):
    """
    Definition of the Filterset for Hash.
    """
    class Meta:
        model = Hash
        fields = ('id', 'software', 'filename')

    def search(self, queryset, name, value):
        return queryset.filter(description__icontains=value)

class FileHashFilterSet(NetBoxModelFilterSet):
    """
    Definition of the Filterset for FileHash.
    """
    class Meta:
        model = FileHash
        fields = ('id', 'algorithm', 'value', 'hash')

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
