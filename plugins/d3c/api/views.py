"""
    These classes are needed for bulk update and delete operations.
"""
from netbox.api.viewsets import NetBoxModelViewSet
from .. import filtersets, models
from .serializers import DeviceFindingSerializer, SoftwareSerializer, CommunicationSerializer, CommunicationFindingSerializer, MappingSerializer, ProductRelationshipSerializer, XGenericUriSerializer, HashSerializer, FileHashSerializer

from django.db.models import Count

class DeviceFindingViewSet(NetBoxModelViewSet):
    """
    ViewSet for DeviceFinding.
    """
    queryset = models.DeviceFinding.objects.all()
    serializer_class = DeviceFindingSerializer
    filterset_class = filtersets.DeviceFindingFilterSet


class SoftwareViewSet(NetBoxModelViewSet):
    """
    ViewSet for Software.
    """
    queryset = models.Software.objects.all() 
    serializer_class = SoftwareSerializer
    filterset_class = filtersets.SoftwareFilterSet

class ProductRelationshipViewSet(NetBoxModelViewSet):
    """
    ViewSet for ProductRelationships.
    """
    queryset = models.ProductRelationship.objects.all() 
    serializer_class = ProductRelationshipSerializer
    filterset_class = filtersets.ProductRelationshipFilterSet

class XGenericUriViewSet(NetBoxModelViewSet):
    """
    ViewSet for XGenericUri.
    """
    queryset = models.XGenericUri.objects.all() 
    serializer_class = XGenericUriSerializer
    filterset_class = filtersets.XGenericUriFilterSet

class HashViewSet(NetBoxModelViewSet):
    """
    ViewSet for XGenericUri.
    """
    queryset = models.Hash.objects.all() 
    serializer_class = HashSerializer
    filterset_class = filtersets.HashFilterSet

class FileHashViewSet(NetBoxModelViewSet):
    """
    ViewSet for XGenericUri.
    """
    queryset = models.FileHash.objects.all() 
    serializer_class = FileHashSerializer
    filterset_class = filtersets.FileHashFilterSet

class CommunicationViewSet(NetBoxModelViewSet):
    """
    ViewSet for Communication.
    """
    queryset = models.Communication.objects.all() 
    serializer_class = CommunicationSerializer
    filterset_class = filtersets.CommunicationFilterSet


class CommunicationFindingViewSet(NetBoxModelViewSet):
    """
    ViewSet for CommunicationFinding.
    """
    queryset = models.CommunicationFinding.objects.all() 
    serializer_class = CommunicationFindingSerializer
    filterset_class = filtersets.CommunicationFindingFilterSet


class MappingViewSet(NetBoxModelViewSet):
    """
    Viewset for Mapping.
    """
    queryset = models.Mapping.objects.all()
    serializer_class = MappingSerializer
    filterset_class = filtersets.MappingFilterSet
