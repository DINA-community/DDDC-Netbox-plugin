from netbox.graphql.types import NetBoxObjectType
from . import models

class Software(NetBoxObjectType):
    """
    Software definition for the GraphQL API.
    """
    class Meta:
        model = models.Software
        fields = '__all__'


class Communication(NetBoxObjectType):
    """
    Communication definition for the GraphQL API.
    """
    class Meta:
        model = models.Communication
        fields = '__all__'


class DeviceFinding(NetBoxObjectType):
    """
    DeviceFinding definition for the GraphQL API.
    """
    class Meta:
        model = models.DeviceFinding
        fields = '__all__'


class CommunicationFinding(NetBoxObjectType):
    """
    CommunicationFinding definition for the GraphQL API.
    """
    class Meta:
        model = models.CommunicationFinding
        fields = '__all__'


class Mapping(NetBoxObjectType):
    """
    Mapping definition for the GraphQL API.
    """
    class Meta:
        model = models.Mapping
        fields = '__all__'
