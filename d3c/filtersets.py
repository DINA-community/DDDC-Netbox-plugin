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
        fields = {
            'id': ['exact'],
            'has_predicted_device': ['exact'],
            'confidence': ['exact', 'lt', 'gt'],
            'source': ['icontains'],
            'manufacturer': ['icontains'],
            'device_role': ['icontains'],
            'device_type': ['icontains'],
            'ip_address': ['icontains'],
            'mac_address': ['icontains'],
            'network_protocol': ['icontains'],
            'transport_protocol': ['icontains'],
            'application_protocol': ['icontains'],
            'port': ['icontains'],
        }

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
    source = django_filters.CharFilter(field_name="source", lookup_expr="icontains")
    source_ip = django_filters.CharFilter(field_name="source_ip", lookup_expr="icontains")
    destination_ip = django_filters.CharFilter(field_name="destination_ip", lookup_expr="icontains")
    destination_port = django_filters.CharFilter(field_name="destination_port", lookup_expr="icontains")
    network_protocol = django_filters.CharFilter(field_name="network_protocol", lookup_expr="icontains")
    transport_protocol = django_filters.CharFilter(field_name="transport_protocol", lookup_expr="icontains")
    application_protocol = django_filters.CharFilter(field_name="application_protocol", lookup_expr="icontains")
    predicted_src_device = django_filters.CharFilter(field_name="predicted_src_device", lookup_expr="icontains")
    predicted_dst_device = django_filters.CharFilter(field_name="predicted_dst_device", lookup_expr="icontains")

    class Meta:
        model = CommunicationFinding

        fields = ('id',  'has_2_predicted_devices')

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
