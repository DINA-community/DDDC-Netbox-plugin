from django.db import models
from netbox.models import NetBoxModel
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.urls import reverse
from ipam.models import IPAddress
from dcim.models import Interface, MACAddress
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned, ValidationError
from django.urls.exceptions import NoReverseMatch
import re
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from utilities.choices import ChoiceSet
from django.contrib.postgres.fields import ArrayField
from django.contrib.contenttypes.fields import GenericRelation


class Dummy(NetBoxModel):
    """
    A dummy model which enables the plugin to track whether it was already initialized.
    Such an object will be created through django's request_started-signal in __init__.py.
    """
    initialized = models.BooleanField(default=False)


class Software(NetBoxModel):
    """
    Software represents a program installed on a device or as a subcomponent of another software.
    Relationships between devices and software can be modeled through ProductRelationships.
    """
    name = models.CharField(
        max_length=50,
        blank=False,
        null=False
    )
    is_firmware = models.BooleanField(
        null=True,
        blank=True
    )
    version = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    cpe = models.CharField(
        max_length=1000,
        blank=True,
        null=True
    )
    purl = models.CharField(
        max_length=1000,
        blank=True,
        null=True
    )
    # arrayfield
    sbom_urls = ArrayField(
        base_field=models.CharField(
            max_length=1000,
            blank=True,
            null=True
        ),
        verbose_name='sbom urls',
        blank=True,
        null=True
    )

    sourcerel = GenericRelation(
        to='d3c.ProductRelationship',
        content_type_field='source_type',
        object_id_field='source_id'
    )

    destinationrel = GenericRelation(
        to='d3c.ProductRelationship',
        content_type_field='destination_type',
        object_id_field='destination_id'
    )

    xgenericuri = GenericRelation(
        to='d3c.XGenericUri',
    )

    def get_absolute_url(self):
        return reverse('plugins:d3c:software', args=[self.pk])

    class Meta:
        verbose_name_plural = 'Software'

    def __str__(self):
        version = ' ' + self.version if self.version else ''
        return self.name + version

    @property
    def docs_url(self):
        return None


XGENERICURI_PARENT_MODELS = Q(
    Q(app_label='dcim', model='devicetype') |
    Q(app_label='d3c', model='software')
)


class XGenericUri(NetBoxModel):
    """
    XGenericUri represents a generic URI used as an identification helper in the Common Security Advisory Framework
    (CSAF), a machine-processable format for security advisories. An XGenericUri can be assigned to either a
    Device Type or Software. The assigned object is stored within 'content_object' and is implemented, as is
    customary in Netbox, through Generic Relations, see:
    https://docs.djangoproject.com/en/4.2/ref/contrib/contenttypes/#generic-relations
    """
    content_type = models.ForeignKey(
        to=ContentType,
        on_delete=models.CASCADE,
        limit_choices_to=XGENERICURI_PARENT_MODELS,
    )

    object_id = models.PositiveBigIntegerField()

    content_object = GenericForeignKey(
        ct_field='content_type',
        fk_field='object_id'
    )

    namespace = models.CharField(
        max_length=1000,
    )

    uri = models.CharField(
        max_length=1000,
    )

    def get_absolute_url(self):
        return reverse('plugins:d3c:xgenericuri', args=[self.pk])

    class Meta:
        verbose_name_plural = 'XGenericUris'

    def __str__(self):
        return 'ID ' + str(self.pk)

    @property
    def docs_url(self):
        return None


class Hash(NetBoxModel):
    """
    A Hash models a filename identification using cryptographic hash values.
    It stores the relationship to software and the concrete filename.
    The actual hash value is specified via a FileHash model.
    """
    software = models.ForeignKey(
        to='d3c.Software',
        on_delete=models.CASCADE,
        related_name='hashes',
    )

    filename = models.CharField(
        max_length=1000,
    )

    def get_absolute_url(self):
        return reverse('plugins:d3c:hash', args=[self.pk])

    class Meta:
        verbose_name_plural = 'Hashes'

    def __str__(self):
        return str(self.filename)

    @property
    def docs_url(self):
        return None


class FileHash(NetBoxModel):
    """
    A FileHash stores the hash value and algorithm.
    This model must be assigned to a Hash object that contains the filename and associated software.
    """
    algorithm = models.CharField(
        max_length=1000,
    )

    value = models.CharField(
        max_length=1000,
    )

    hash = models.ForeignKey(
        to='d3c.Hash',
        on_delete=models.CASCADE,
        related_name='file_hashes',
    )

    def get_absolute_url(self):
        return reverse('plugins:d3c:filehash', args=[self.pk])

    class Meta:
        verbose_name_plural = 'FileHashes'

    def __str__(self):
        return str(self.algorithm) + ' for ' + str(self.hash)

    @property
    def docs_url(self):
        return None


PRODCUT_PARENT_MODELS = Q(
    Q(app_label='dcim', model='device') |
    Q(app_label='d3c', model='software')
)


class ProductRelationshipCategory(ChoiceSet):
    """
    A ProductRelationship represents relationships between device and software components.
    The Categories are derived from CSAF, see:
    https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#3224-product-tree-property---relationships
    """
    DEFAULT_COMPONENT_OF = "1"
    EXTERNAL_COMPONENT_OF = "2"
    INSTALLED_ON = "3"
    INSTALLED_WITH = "4"
    OPTIONAL_COMPONENT_OF = "5"

    CHOICES = (
        (DEFAULT_COMPONENT_OF, 'default_component_of'),
        (EXTERNAL_COMPONENT_OF, 'external_component_of'),
        (INSTALLED_ON, 'installed_on'),
        (INSTALLED_WITH, 'installed_with'),
        (OPTIONAL_COMPONENT_OF, 'optional_component_of'),
    )


class ProductRelationship(NetBoxModel):
    """
    A ProductRelationship represents relationships between device and software components.
    The parent/source and target/destination of a relationship can be either a Device or Software.
    Generic relations, as comonly used in Netbox, are employed to model this concept:
    https://docs.djangoproject.com/en/4.2/ref/contrib/contenttypes/#generic-relations
    """
    source_type = models.ForeignKey(
        to=ContentType,
        on_delete=models.CASCADE,
        limit_choices_to=PRODCUT_PARENT_MODELS,
        related_name='sourceProduct',
    )

    source_id = models.PositiveBigIntegerField()

    source = GenericForeignKey(
        ct_field='source_type',
        fk_field='source_id'
    )

    category = models.CharField(
        max_length=30,
        choices=ProductRelationshipCategory,
    )

    destination_type = models.ForeignKey(
        to=ContentType,
        on_delete=models.CASCADE,
        limit_choices_to=PRODCUT_PARENT_MODELS,
        related_name='destinationProduct',
    )

    destination_id = models.PositiveBigIntegerField()

    destination = GenericForeignKey(
        ct_field='destination_type',
        fk_field='destination_id'
    )

    def get_absolute_url(self):
        return reverse('plugins:d3c:productrelationship', args=[self.pk])

    class Meta:
        verbose_name_plural = 'ProductRelationship'

    def __str__(self):
        return str(self.source) + ' - ' + str(self.get_category_display()) + ' - ' + str(self.destination)

    @property
    def docs_url(self):
        return None


class Communication(NetBoxModel):
    """
    A Communication represents a network connection between two Interfaces.
    """
    source_device = models.ForeignKey(
        to='dcim.Device',
        on_delete=models.CASCADE,
        related_name='sourceForCommunications',
        blank=True,
        null=True
    )
    destination_device = models.ForeignKey(
        to='dcim.Device',
        on_delete=models.CASCADE,
        related_name='destinationForCommunications',
        blank=True,
        null=True
    )
    source_ip_addr = models.ForeignKey(
        to='ipam.IPAddress',
        on_delete=models.CASCADE,
        related_name='sourceIPAddress',
        blank=True,
        null=True
    )
    destination_ip_addr = models.ForeignKey(
        to='ipam.IPAddress',
        on_delete=models.CASCADE,
        related_name='destinationIPAddress',
        blank=True,
        null=True
    )
    destination_port = models.IntegerField(
        blank=True,
        null=True
    )
    network_protocol = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    transport_protocol = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    application_protocol = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )

    def get_absolute_url(self):
        return reverse('plugins:d3c:communication', args=[self.pk])

    @property
    def docs_url(self):
        return None


NEW_DONE = (('NEW', 'NEW'), ('DONE', 'DONE'), ('REJECT', 'REJECT'))
ipv4_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


class DeviceFinding(NetBoxModel):
    """
    A DeviceFindings represents device information obtained by importing data from external information sources,
    such as CSV files or nmap scripts.
    """
    device = models.ForeignKey(
        to='dcim.Device',
        on_delete=models.SET_NULL,
        related_name='device_findings',
        blank=True,
        null=True
    )
    source = models.CharField(
        max_length=50
    )
    confidence = models.DecimalField(
        max_digits=4,
        decimal_places=3,
        blank=True,
        null=True
    )
    device_name = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Device Name'
    )
    status = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    # dcim.Site
    site = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    rack = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    location = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    # dcim.Device
    description = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    device_type = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Device Type'
    )
    serial_number = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Serial Number'
    )
    exposure = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    # dcim.DeviceRole
    device_role = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Device Role'
    )
    # DeviceExtra
    is_safety_critical = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='is Safety Critical'
    )
    network_protocol = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Network Protocol'
    )
    transport_protocol = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Transport Protocol'
    )
    application_protocol = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Application Protocol'
    )
    port = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    # Interface
    # Comma-seperated list allowed
    mac_address = models.CharField(
        max_length=1000,
        blank=True,
        null=True,
        verbose_name='MAC Address'
    )
    # Comma-seperated list allowed
    ip_address = models.CharField(
        max_length=1000,
        blank=True,
        null=True,
        verbose_name='IP Address'
    )
    ip_netmask = models.CharField(
        max_length=2,
        blank=True,
        null=True,
        default='24',
        verbose_name='IP Netmask'
    )
    # InterfaceExtra
    is_router = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='is Router'
    )
    # DeviceType/Manufacturer
    manufacturer = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    oui = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    # DeviceType
    part_number = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Part Number'
    )
    # DeviceTypeExtra
    device_family = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Device Family'
    )
    article_number = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Article Number'
    )
    hardware_version = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Hardware Version'
    )
    hardware_cpe = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Hardware CPE'
    )
    # Software
    software_name = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='Software Name'
    )
    is_firmware = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='is Firmware'
    )
    version = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )

    finding_status = models.CharField(
        max_length=6,
        choices=NEW_DONE,
        default="NEW",
        verbose_name='Finding Status'
    )

    predicted_device = models.ForeignKey(
        to='dcim.Device',
        on_delete=models.SET_NULL,
        related_name='predicted_device_findings',
        blank=True,
        null=True,
        verbose_name='Predicted Device'
    )

    has_predicted_device = models.BooleanField(default=False)  # ToDo get rid of this

    @property
    def docs_url(self):
        return None

    def get_absolute_url(self):
        return reverse('plugins:d3c:devicefinding', args=[self.pk])

    def is_empty(self):
        """
        Checks if any attributes have been set on this DeviceFinding.

        :return: True, if the DeviceFinding does not have any attributes set.
        """
        attribute_list = (self.status, self.site, self.description, self.device_type, self.serial_number,
                          self.device_role, self.is_safety_critical, self.network_protocol, self.transport_protocol,
                          self.application_protocol, self.port, self.is_router, self.manufacturer, self.oui,
                          self.hardware_version, self.hardware_cpe, self.software_name, self.device_name,
                          self.part_number, self.is_firmware, self.version, self.article_number, self.rack,
                          self.location, self.exposure, self.ip_netmask)
        for x in attribute_list:
            if x != None:
                return False
        return True

    def get_device_by_ip(self, ip):
        """
        Performs a lookup for devices with the specified IP-Address.
        :param ip: string, the IP-Address used for the lookup.
        :return: The Device associated  with this IP-Address.
        """
        try:
            source = IPAddress.objects.get(address=ip,
                                           assigned_object_type=ContentType.objects.get_for_model(Interface))
            if source:
                return Interface.objects.get(id=source.assigned_object_id).device
            return None
        except (ObjectDoesNotExist, MultipleObjectsReturned, ValidationError, NoReverseMatch) as error:
            return None

    def get_device_by_mac(self, mac_address):
        """
        Performs a lookup for devices with the specified MAC-Address.
        :param mac_address: string, the MAC-Address used for the lookup.
        :return: The Device associated  with this MAC-Address.
        """
        try:
            source = MACAddress.objects.get(mac_address=mac_address,
                                            assigned_object_type=ContentType.objects.get_for_model(Interface))
            if source:
                return Interface.objects.get(id=source.assigned_object_id).device
            return None
        except (ObjectDoesNotExist, MultipleObjectsReturned, ValidationError, NoReverseMatch) as error:
            return None

    def get_matched_device(self, save=True):
        """
        Performs the device lookup for a single DevicefFnding.

        :param save: True if the changes should be made persistent.
        :return: True if successful, False otherwise.
        """
        guessed_device = None
        device_by_ip = None
        device_by_mac = None

        if self.ip_address:
            res = ipv4_pattern.search(self.ip_address)
            if res:
                ipaddress = f'{res[0]}/{self.ip_netmask}'
                device_by_ip = self.get_device_by_ip(ipaddress)

        if self.mac_address:
            device_by_mac = self.get_device_by_mac(self.mac_address)

        if device_by_ip and device_by_mac and (device_by_ip.pk != device_by_mac.pk):
            self.predicted_device = None
        elif device_by_ip:
            self.predicted_device = device_by_ip
        elif device_by_mac:
            self.predicted_device = device_by_mac
        else:
            self.predicted_device = None

        self.has_predicted_device = bool(self.predicted_device)

        if self.has_predicted_device and self.is_empty():
            self.finding_status = "DONE"
            save = True

        if save:
            self.save()

        return self.predicted_device


def df_device_lookup():
    """
    Performs the operation when clicking the Device Lookup Button in the Table-View of DeviceFinding.

    :return: True, if the device lookup was successful.
    """
    try:
        qs = DeviceFinding.objects.filter(device__isnull=True, finding_status='NEW')
        for device_finding in qs:
            device_finding.get_matched_device()
        return True
    except BaseException as e:
        return False


@receiver([post_save, post_delete], sender=Interface)
def interface_check_asignment(sender, instance, **kwargs):
    """
    This function is executed every time a new Interface has been created, edited, or deleted.
    In such cases, the CommunicationFindings are updated automatically. The automatic update of the
    DeviceFindings was too time-consuming, therefore not implemented here.
    """
    communicationfindings_update_founddevices()


@receiver([post_save, post_delete], sender=IPAddress)
def ip_check_asignment(sender, instance, **kwargs):
    """
    This function is executed every time a new IP-Address has been created, edited, or deleted.
    In such cases, the CommunicationFindings are updated automatically. The automatic update of the
    DeviceFindings was too time-consuming, therefore not implemented here.
    """
    communicationfindings_update_founddevices()


class CommunicationFinding(NetBoxModel):
    """
    A CommunicationFindings represents layer 3 network communication information.
    """
    source = models.CharField(
        max_length=50
    )
    source_ip = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    destination_ip = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    destination_port = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    network_protocol = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    transport_protocol = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    application_protocol = models.CharField(
        max_length=50,
        blank=True,
        null=True
    )
    finding_status = models.CharField(
        max_length=6,
        choices=NEW_DONE,
        default="NEW"
    )
    predicted_src_device = models.ForeignKey(
        to='dcim.Device',
        on_delete=models.SET_NULL,
        related_name='predicted_src_device',
        blank=True,
        null=True
    )
    predicted_dst_device = models.ForeignKey(
        to='dcim.Device',
        on_delete=models.SET_NULL,
        related_name='predicted_dst_device',
        blank=True,
        null=True
    )

    has_predicted_src_device = models.BooleanField(default=False)
    has_predicted_dst_device = models.BooleanField(default=False)
    has_2_predicted_devices = models.BooleanField(default=False)

    @property
    def docs_url(self):
        return None

    def get_absolute_url(self):
        return reverse('plugins:d3c:communicationfinding', args=[self.pk])

    def get_device_by_ip(self, ip):
        """
        Performs a lookup for devices with the specified IP-Address.
        :param ip: string, the IP-Address used for the lookup.
        :return: The Device associated  with this IP-Address.
        """
        try:
            source = IPAddress.objects.get(address=ip,
                                           assigned_object_type=ContentType.objects.get_for_model(Interface))
            if source:
                return Interface.objects.get(id=source.assigned_object_id).device
            return None
        except (ObjectDoesNotExist, MultipleObjectsReturned, ValidationError, NoReverseMatch) as error:
            return None

    def get_matched_device(self, save=True):
        """
        Performs the communication lookup for a single CommunicationFinding.

        :param save: True if the changes should be made persistent.
        :return: True if successful, False otherwise.
        """
        source_device_by_ip = None
        destination_device_by_ip = None

        if self.source_ip:
            res = ipv4_pattern.search(self.source_ip)
            if res:
                ipaddress = res[0] + "/24"  # ToDo: More Logic needed
                source_device_by_ip = self.get_device_by_ip(ipaddress)

        if self.destination_ip:
            res = ipv4_pattern.search(self.destination_ip)
            if res:
                ipaddress = res[0] + "/24"  # ToDo: More Logic needed
                destination_device_by_ip = self.get_device_by_ip(ipaddress)

        if source_device_by_ip != None:
            self.predicted_src_device = source_device_by_ip
        else:
            self.predicted_src_device = None
        self.has_predicted_src_device = bool(self.predicted_src_device)

        if destination_device_by_ip != None:
            self.predicted_dst_device = destination_device_by_ip
        else:
            self.predicted_dst_device = None
        self.has_predicted_dst_device = bool(self.predicted_dst_device)

        self.has_2_predicted_devices = self.has_predicted_src_device and self.has_predicted_dst_device

        if save:
            self.save()

        return (source_device_by_ip, destination_device_by_ip)


def communicationfindings_update_founddevices():
    """
     This function is executed every time an Interface or IP-Address has been created, edited, or deleted.
     In such cases, the CommunicationFindings are updated automatically.
     """
    for x in CommunicationFinding.objects.all():
        if x.finding_status == "NEW" and (x.predicted_src_device == None or x.predicted_dst_device == None):
            x.get_matched_device()


@receiver(post_save, sender=CommunicationFinding)
def communicationfinding_check_asignment(sender, instance, **kwargs):
    """
    This function is executed every time a CommunicationFinding has been updated.
    """
    try:
        cf = CommunicationFinding.objects.get(pk=instance.pk)
        src, dst = cf.get_matched_device(False)
        if src and dst:
            CommunicationFinding.objects.filter(pk=instance.pk).update(predicted_src_device=src)
            CommunicationFinding.objects.filter(pk=instance.pk).update(predicted_dst_device=dst)
            if src:
                CommunicationFinding.objects.filter(pk=instance.pk).update(has_predicted_src_device=True)
            else:
                CommunicationFinding.objects.filter(pk=instance.pk).update(has_predicted_src_device=False)
            if dst:
                CommunicationFinding.objects.filter(pk=instance.pk).update(has_predicted_dst_device=True)
            else:
                CommunicationFinding.objects.filter(pk=instance.pk).update(has_predicted_dst_device=False)
    except BaseException as e:
        pass


class Mapping(NetBoxModel):
    """
    A Mapping to convert a source (CSV) into a target (DeviceFinding).
    """
    name = models.CharField(
        max_length=50,
        blank=False,
        null=False
    )
    type = models.CharField(
        max_length=10,
        blank=False,
        null=False
    )
    data = models.JSONField(
        max_length=1000,
        blank=True,
        null=False
    )

    def get_absolute_url(self):
        return reverse('plugins:d3c:mapping', args=[self.pk])

    class Meta:
        verbose_name_plural = 'Mappings'

    def __str__(self):
        return self.type + ":" + self.name


FILEHASH_ALGO=(
    ('blake2b512', 'blake2b512'),
    ('blake2s256', 'blake2s256'),
    ('md4', 'md4'),
    ('md5', 'md5'),
    ('md5-sha1', 'md5-sha1'),
    ('ripemd', 'ripemd'),
    ('ripemd160', 'ripemd160'),
    ('rmd160', 'rmd160'),
    ('sha1', 'sha1'),
    ('sha224', 'sha224'),
    ('sha256', 'sha256'),
    ('sha3-224', 'sha3-224'),
    ('sha3-256', 'sha3-256'),
    ('sha3-384', 'sha3-384'),
    ('sha384', 'sha384'),
    ('sha512', 'sha512'),
    ('sha512-224', 'sha512-224'),
    ('sha512-256', 'sha512-256'),
    ('shake128', 'shake128'),
    ('shake256', 'shake256'),
    ('sm3', 'sm3'),
    ('ssl3-md5', 'ssl3-md5'),
    ('ssl3-sha1', 'ssl3-sha1'),
    ('whirlpool', 'whirlpool'),
)
