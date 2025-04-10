"""
    These serializers are used to log changes to the Changelog.
"""
from rest_framework import serializers

from netbox.api.serializers import NetBoxModelSerializer
from dcim.api.serializers import DeviceSerializer
from ..models import (Dummy, DeviceFinding, Software, Communication,
                      CommunicationFinding, Mapping, ProductRelationship, PRODCUT_PARENT_MODELS,
                      XGENERICURI_PARENT_MODELS, XGenericUri, FileHash, Hash)
from django.db.models import Q
from netbox.api.fields import ContentTypeField
from django.contrib.contenttypes.models import ContentType
from drf_spectacular.utils import extend_schema_field
from utilities.api import get_serializer_for_model


class DeviceFindingSerializer(NetBoxModelSerializer):
    """
    REST API Model Serializer for DeviceFindings.
    """
    url = serializers.HyperlinkedIdentityField(view_name='plugins-api:d3c-api:devicefinding-detail')

    class Meta:
        model = DeviceFinding
        fields = ('id', 'device', 'url', 'source', 'confidence',
                  'description', 'device_role', 'serial_number', 'device_name', 'status', 'site', 'rack', 'location',
                  'device_type', 'serial_number', 'device_role', 'is_safety_critical',
                  'ip_address', 'ip_netmask', 'mac_address', 'transport_protocol', 'application_protocol', 'port',
                  'is_router', 'manufacturer', 'oui', 'device_family',
                  'article_number', 'part_number', 'hardware_version', 'hardware_cpe', 'software_name',
                  'is_firmware', 'version', 'exposure', 'has_predicted_device', 'predicted_device')


class SoftwareSerializer(NetBoxModelSerializer):
    """
    REST API Model Serializer for Software.
    """
    class Meta:
        model = Software
        fields = ('id', 'display', 'name', 'is_firmware', 'version', 'cpe', 'purl', 'sbom_urls',
                  'custom_fields', 'created', 'last_updated')


##
class CommunicationSerializer(NetBoxModelSerializer):
    """
    REST API Model Serializer for Communication.
    """
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:d3c-api:communication-detail'
    )

    source_device = DeviceSerializer(read_only=True, nested=True)

    class Meta:
        model = Communication
        fields = ('id', 'url', 'source_device', 'destination_device', 'source_ip_addr', 'destination_ip_addr',
                  'destination_port', 'network_protocol', 'transport_protocol', 'application_protocol')


class CommunicationFindingSerializer(NetBoxModelSerializer):
    """
    REST API Model Serializer for CommunicationFinding.
    """
    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:d3c-api:communicationfinding-detail'
    )

    class Meta:
        model = CommunicationFinding
        fields = ('id', 'url', 'source', 'source_ip', 'destination_ip', 'destination_port', 'network_protocol',
                  'transport_protocol', 'application_protocol')


class MappingSerializer(NetBoxModelSerializer):
    """
    REST API Model Serializer for Mapping.
    """
    class Meta:
        model = Mapping
        fields = ('id', 'type', 'name', 'data', 'display')


class DummySerializer(NetBoxModelSerializer):
    """
    REST API Model Serializer for DDDCAdmin.
    """

    class Meta:
        model = Dummy
        fields = ('id', 'initialized')


class ProductRelationshipSerializer(NetBoxModelSerializer):
    """
    REST API Model Serializer for ProductRelationship.
    """
    source_type = ContentTypeField(
        queryset=ContentType.objects.filter(PRODCUT_PARENT_MODELS),
        required=True
    )
    source = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = ProductRelationship
        fields = [
            'id', 'source_type', 'source_id', 'source', 'category', 'destination_type', 'destination_id', 'destination',
        ]

    @extend_schema_field(serializers.JSONField(allow_null=True))
    def get_source(self, obj):
        serializer = get_serializer_for_model(obj.source)
        context = {'request': self.context['request']}
        return serializer(obj.source, nested=True, context=context).data

    @extend_schema_field(serializers.JSONField(allow_null=True))
    def get_destination(self, obj):
        serializer = get_serializer_for_model(obj.destination)
        context = {'request': self.context['request']}
        return serializer(obj.destination, nested=True,context=context).data


class XGenericUriSerializer(NetBoxModelSerializer):
    """
    REST API Model Serializer for XGenericUri.
    """
    content_type = ContentTypeField(
        queryset=ContentType.objects.filter(XGENERICURI_PARENT_MODELS),
        required=True
    )

    content_object = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = XGenericUri
        fields = [
            'id',  'content_type', 'content_object', 'namespace', 'uri'
        ]

    @extend_schema_field(serializers.JSONField(allow_null=True))
    def get_content_object(self, obj):
        serializer = get_serializer_for_model(obj.content_object)
        context = {'request': self.context['request']}
        return serializer(obj.content_object, nested=True, context=context).data


class FileHashSerializer(NetBoxModelSerializer):
    """
    REST API Model Serializer for FileHash.
    """
    class Meta:
        model = FileHash
        fields = ('id', 'algorithm', 'value', 'hash', 'tags')


class HashSerializer(NetBoxModelSerializer):
    """
    REST API Model Serializer for Hash.
    """
    class Meta:
        model = Hash
        fields = ('id', 'filename', 'tags')
