"""
    This file provides all the table definitions implemented and used by the D3C-Plugin.
"""

import django_tables2 as tables
from django_tables2.utils import Accessor
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from netbox.tables import NetBoxTable, columns
from .models import (DeviceFinding, Software, Communication, CommunicationFinding,
                     Mapping, ProductRelationship, XGenericUri, FileHash, Hash)
from .device_update import get_current_value_for_device
from .string_checker import StringChecker
from .string_helper import disassebmle_role
from .string_normalizer import StringNormalizer
from .utils import time_start, time_end
from django.contrib.contenttypes.models import ContentType

TRUNCATE_TEMPLATE = '<data-toggle="tooltip" title="{{{{record.{0}}}}}">{{{{record.{0}|truncatewords:3}}}}'

CREATE_DEVICE_BUTTON = """
{% load helpers %}
{% if record.has_predicted_device  %}
{% else %}
    {% if record.ip_address or  record.mac_address %}
    <a href="{% url 'plugins:d3c:devicefinding_createdevice'%}?df={{ record.pk }}&return_url={{ request.path }}" title="Create Device" class="btn btn-primary btn-sm">
      <i class="mdi mdi-plus-thick" aria-hidden="true"></i>
      <a />
    {% endif %}
{% endif %}
"""


APPLY_DF_BUTTON = """
{% load helpers %}
<a href="{% url 'plugins:d3c:devicefinding_apply'%}?device={{ object.pk }}&finding={{ record.pk }}&rsp=True&return_url={{ request.path }}" title="Apply DeviceFinding" class="btn btn-primary btn-sm">
    <i class="mdi mdi-arrow-u-left-top-bold" aria-hidden="true"></i>
<a />
"""


class FileHashTable(NetBoxTable):
    """
        Table for the FileHash model.
    """
    hash = tables.Column(
        verbose_name='Hash',
        accessor=Accessor('hash'),
        linkify=True
    )

    class Meta(NetBoxTable.Meta):
        model = FileHash
        fields = (
            'id', 'algorithm', 'value', 'hash'
        )
        default_columns = ('id', 'algorithm', 'value', 'hash')


class HashTable(NetBoxTable):
    """
        Table for the Hash model.
    """
    software = tables.Column(
        verbose_name='Software',
        accessor=Accessor('software'),
        linkify=True
    )

    fh = tables.Column(empty_values=(), verbose_name='FileHashes Count')


    class Meta(NetBoxTable.Meta):
        model = Hash
        fields = (
            'id', 'filename', 'software'
        )
        default_columns = ('id', 'software', 'filename', 'fh')

    def render_fh(self, record):
        return FileHash.objects.filter(hash=record.id).count()


class XGenericUriTable(NetBoxTable):
    """
        Table for the XGenericUri model.
    """
    content_object = tables.Column(
        linkify=True,
        orderable=False,
        verbose_name='Parent (DeviceType or Software)'
    )

    class Meta(NetBoxTable.Meta):
        model = XGenericUri
        fields = (
            'id', 'content_object', 'namespace', 'uri'
        )
        default_columns = ('id', 'content_object', 'namespace', 'uri')


class ProductRelationshipTable(NetBoxTable):
    """
        Table for the ProductRelationship model.
    """
    source = tables.Column(
        linkify=True,
        orderable=False,
        verbose_name='Parent'
    )

    destination = tables.Column(
        linkify=True,
        orderable=False,
        verbose_name='Target'
    )

    class Meta(NetBoxTable.Meta):
        model = ProductRelationship
        fields = (
            'id', 'source', 'category', 'destination'
        )
        default_columns = ('id', 'source', 'category', 'destination')


class UnassignedDeviceFindingTable(NetBoxTable):
    """
        Table for the DeviceFinding model (not Device specific).
    """

    actions = columns.ActionsColumn(
        actions=('edit',),
        extra_buttons=CREATE_DEVICE_BUTTON
    )

    has_predicted_device = columns.BooleanColumn()

    predicted_device = tables.Column(
        linkify=True
    )

    ip_address = tables.Column(verbose_name="IP Address")

    mac_address = tables.Column(verbose_name="MAC Address")

    confidence = tables.Column(verbose_name="Confidence")

    class Meta(NetBoxTable.Meta):
        model = DeviceFinding
        fields = ('id', 'source', 'confidence', 'device_role', 'device_name', 'status', 'site', 'rack', 'location',
                  'description', 'device_type', 'serial_number', 'device_role', 'is_safety_critical',
                  'ip_address', 'ip_netmask', 'mac_address', 'network_protocol', 'transport_protocol', 'application_protocol', 'port',
                  'is_router', 'manufacturer', 'oui', 'device_family', 'article_number', 'part_number',
                  'hardware_version', 'hardware_cpe', 'software_name', 'is_firmware', 'version',
                  'exposure', 'device', 'has_predicted_device', 'predicted_device', 'finding_status')
        default_columns = ('id', 'source', 'has_predicted_device', 'predicted_device', 'ip_address', 'mac_address',
                           'manufacturer', 'transport_protocol', 'application_protocol', 'port', 'is_router')

    def render_confidence(self, value, column):
        if value < 0 or value > 1:
            column.attrs = {'td': {'class': 'p-3 mb-2 bg-danger text-white'}}
        else:
            column.attrs = {'td': {}}
        return value



class RadioColumn(tables.Column):
    """
        Column with radio buttons for the DeviceFinding table (Device specific).
    """
    templateFirst = '<input type="radio" id="{}" name="{}" value="{}" /> <label for="{}"><b>{}</b></label>'
    templateRest = '<br><input type="radio" id="{}" name="{}" value="{}" /> <label for="{}">{}</label>'
    templateFooter = '<input type="radio" id="{}" name="{}" value="{}" checked /> <label for="{}">{}</label>'

    def __init__(self, *args, **kwargs):
        table = None
        super().__init__(*args, **kwargs)

    def setTable(self, table):
        self.table = table

    def render(self, **kwargs):
        bCol = kwargs.get('bound_column')
        record = kwargs.get('record')
        colName = bCol.name
        value = kwargs.get('value')
        if self.table:
            time_start('getRecordValue')
            value = self.table.getRecordValue(record, colName, value)
            time_end()
        inputId = "" + str(record.id) + "-" + colName
        if isinstance(value, list) and not isinstance(value, str):
            html = ''
            first = True
            idx = 1
            for subVal in value:
                subInputId = inputId + str(idx)
                if first:
                    html += format_html(self.templateFirst, subInputId, colName, subVal, subInputId, subVal)
                    first = False
                else:
                    html += format_html(self.templateRest, subInputId, colName, subVal, subInputId, subVal)
                idx += 1
            return mark_safe(html)
        return format_html(self.templateFirst, inputId, colName, value, inputId, value)

    def render_footer(self, bound_column, table):
        colName = bound_column.name
        inputId = "0-" + colName
        curValue = get_current_value_for_device(table.getDevice(), colName)
        return format_html(self.templateFooter, inputId, colName, "", inputId, curValue)


class SelectColumn(tables.Column):
    """
        Column with select buttons for the DeviceFinding table (Device specific), especially for software and services.
    """
    template = '<input type="checkbox" id="{}" name="{}" value="{}" checked /> <label for="{}">{}</label>'
    def render(self, **kwargs):
        bCol = kwargs.get('bound_column')
        record = kwargs.get('record')
        colName = bCol.name
        value = kwargs.get('value')
        inputName = colName + "-" + str(record.id)
        inputId = inputName
        return format_html(self.template, inputId, inputName, inputId, inputId, value)


class SelectGroupColumn(tables.Column):
    """
        Column for grouping elements, especially for software and services.
    """
    group = None
    def setGroup(self, group):
        self.group = group

    def render(self, **kwargs):
        bCol = kwargs.get('bound_column')
        record = kwargs.get('record')
        colName = bCol.name
        inputId = colName + "-" + str(record.id)
        check = self.group.get('check')
        valid = check(record)
        if valid:
            return format_html('<input type="checkbox" id = "{}" name="{}" value="{}" /> <label for="{}">Add</label>', inputId, inputId, inputId, inputId)
        return ''


class ValueColumn(tables.Column):
    def render(self, **kwargs):
        bCol = kwargs.get('bound_column')
        record = kwargs.get('record')
        colName = bCol.name
        value = kwargs.get('value')
        inputId = colName + "-" + str(record.id)
        return format_html('<input type="hidden" id = "{}" name="{}" value="{}" />{}', inputId, inputId, value, value)


class DeviceFindingForDeviceTable(NetBoxTable):
    """
        Table for the DeviceFinding model (Device specific).

    """
    selectableFields = ('device_role', 'device_name', 'status', 'site', 'rack', 'location', 'description',
                        'device_type', 'serial_number', 'is_safety_critical',
                        'manufacturer', 'oui', 'device_family', 'article_number', 'part_number', 'hardware_version',
                        'hardware_cpe', 'software_name', 'is_firmware', 'version', 'exposure', 'device')
    groupedFields = {
        'service': {
            'columns': ['ip_address', 'network_protocol', 'transport_protocol', 'application_protocol', 'port'],
            'class': 'highlight',
            'check': lambda record: record.network_protocol or record.transport_protocol
        },
        'software': {
            'columns': ['software_name', 'is_firmware', 'version'],
            'class': 'highlight',
            'check': lambda record: record.software_name or record.is_firmware or record.version
        }
    }
    normalizedFields = {'device_role', 'device_name', 'device_type', 'manufacturer'}
    sn = StringNormalizer()

    def __init__(self, *args, extra_columns=None, **kwargs):
        self.device = None
        self.stringCheckerEnabled = False
        self.stringNormalizerEnabled = False
        for colName in self.selectableFields:
            column = RadioColumn()
            self.base_columns[colName] = column
        for group, item in self.groupedFields.items():
            clazz = item.get('class');
            columns = item.get('columns')
            groupColumn = SelectGroupColumn(empty_values=[], attrs={"td": {"class": clazz}})
            groupColumn.setGroup(item)
            self.base_columns[group] = groupColumn
            for colName in columns:
                self.base_columns[colName] = ValueColumn(attrs={"td": {"class": clazz}})
        super().__init__(*args, extra_columns=extra_columns, **kwargs)
        # super().__init__ makes a deep-copy of base_columns, breaking
        # the table we would have set above
        for column in self.columns.columns.values():
            if isinstance(column.column, RadioColumn):
                column.column.setTable(self)

    def setStringCheckerEnabled(self, enabled):
        self.stringCheckerEnabled = enabled

    def setStringNormalizerEnabled(self, enabled):
        self.stringNormalizerEnabled = enabled

    def setDevice(self, device):
        self.device = device

    def getDevice(self):
        return self.device

    def getRecordValue(self, record, colName, dfltValue):
        if colName not in self.normalizedFields:
            return dfltValue
        if colName == 'device_role':
            value = disassebmle_role(dfltValue)
            if value:
                finalValue = [dfltValue]
                for entry in value:
                    if entry != dfltValue:
                        finalValue.append(entry)
                return finalValue
        if self.stringNormalizerEnabled:
            time_start('normalize')
            value = self.sn.normalize(dfltValue, colName)
            time_end()
            if value:
                finalValue = [dfltValue]
                if value != dfltValue:
                    finalValue.append(value)
                return finalValue
        if self.stringCheckerEnabled:
            from .views import S_CHECKER
            if colName in S_CHECKER and len(dfltValue) > 4:
                time_start('string_check')
                value = S_CHECKER[colName].check_candidates(dfltValue)
                time_end()
                if value:
                    finalValue = [dfltValue]
                    for entry in value:
                        if entry != dfltValue:
                            finalValue.append(entry)
                    return finalValue
        return dfltValue

    id = SelectColumn()

    actions = columns.ActionsColumn(
        actions=('edit',),
        extra_buttons=APPLY_DF_BUTTON
    )

    class Meta(NetBoxTable.Meta):
        model = DeviceFinding
        fields = ('id', 'source', 'confidence', 'device_role', 'device_name', 'status', 'site', 'rack', 'location',
                  'description', 'device_type', 'serial_number', 'is_safety_critical', 'mac_address', 'ip_address', 'ip_netmask',
                  'network_protocol', 'transport_protocol', 'application_protocol', 'port', 'manufacturer',
                  'oui', 'device_family', 'article_number', 'part_number', 'hardware_version',  'hardware_cpe',
                  'software_name', 'is_firmware', 'version', 'exposure', 'device', 'finding_status')
        default_columns = ('id', 'source', 'confidence', 'device_role', 'device_name', 'status', 'site', 'rack',
                           'location','description', 'device_type', 'serial_number', 'is_safety_critical',
                           'mac_address', 'service', 'ip_address', 'ip_netmask', 'network_protocol', 'transport_protocol',
                           'application_protocol', 'port', 'manufacturer', 'oui', 'device_family',
                           'article_number', 'part_number', 'hardware_version', 'hardware_cpe', 'software', 'software_name',
                           'is_firmware', 'version', 'cpe', 'exposure',)
        sequence = ('id', 'source', 'confidence', 'device_role', 'device_name', 'status', 'site', 'rack', 'location',
                    'description', 'device_type', 'serial_number', 'is_safety_critical', 'mac_address', 'service',
                    'ip_address', 'ip_netmask', 'network_protocol', 'transport_protocol', 'application_protocol', 'port',
                    'manufacturer', 'oui', 'device_family', 'article_number', 'part_number', 'hardware_version',
                    'hardware_cpe', 'software', 'software_name', 'is_firmware', 'version', 'exposure', 'device', 'finding_status')


class DeviceFindingTable(NetBoxTable):
    """
        Table for the bulk delete operation of DeviceFinding.
    """
    actions = columns.ActionsColumn(
        actions=('edit',),
        extra_buttons=APPLY_DF_BUTTON
    )

    manufacturer = tables.TemplateColumn(TRUNCATE_TEMPLATE.format('manufacturer'))

    devicetype = tables.TemplateColumn(TRUNCATE_TEMPLATE.format('device_type'))

    oui = tables.TemplateColumn(TRUNCATE_TEMPLATE.format('oui'))

    class Meta(NetBoxTable.Meta):
        model = DeviceFinding
        fields = ('id', 'source', 'confidence', 'device_role', 'device_name', 'status', 'site', 'rack', 'location',
                  'description', 'device_type', 'serial_number', 'is_safety_critical', 'ip_address', 'ip_netmask', 'mac_address',
                  'network_protocol', 'transport_protocol', 'application_protocol', 'port', 'is_router',
                  'manufacturer', 'oui', 'device_family', 'article_number', 'part_number', 'hardware_version',
                  'hardware_cpe', 'software_name', 'is_firmware', 'version', 'exposure', 'device', 'finding_status')
        default_columns = ('id', 'source', 'manufacturer', 'device_type', 'oui', 'device_family',
                           'network_protocol', 'transport_protocol', 'application_protocol', 'port')


class SoftwareTable(NetBoxTable):
    """
        Table for the Software model.
    """
    sbom_url_count = tables.Column(empty_values=(), verbose_name='SBOM url Count')

    hashes_count = tables.Column(empty_values=(), verbose_name='Hashes Count')

    xgenericuri_count = tables.Column(empty_values=(), verbose_name='XGenericUri Count')

    parent_rel_count = tables.Column(empty_values=(), verbose_name='Parent Count')

    target_rel_count = tables.Column(empty_values=(), verbose_name='Target Count')

    class Meta(NetBoxTable.Meta):
        model = Software
        fields = ('id', 'name', 'is_firmware', 'version', 'cpe',  'purl',
                  'sbom_url_count', 'hashes_count', 'xgenericuri_count', 'parent_rel_count', 'target_rel_count')
        default_columns = ('id', 'name', 'is_firmware', 'version', 'cpe', 'purl', 'sbom_url_count',
                           'hashes_count', 'xgenericuri_count', 'parent_rel_count', 'target_rel_count')

    def render_sbom_url_count(self, record):
        return len(record.sbom_urls) if record.sbom_urls else 0

    def render_hashes_count(self, record):
        return Hash.objects.filter(software=record.id).count()

    def render_parent_rel_count(self, record):
        return ProductRelationship.objects.filter(source_type_id=ContentType.objects.get_for_model(Software),
                                                  source_id=record.pk).count()

    def render_target_rel_count(self, record):
        return ProductRelationship.objects.filter(destination_type_id=ContentType.objects.get_for_model(Software),
                                                  destination_id=record.pk).count()



    def render_xgenericuri_count(self, record):
        return record.xgenericuri.count()


class CommunicationTable(NetBoxTable):
    """
        Table for the Communication model.
    """
    source_device = tables.Column(
        linkify=True,
        verbose_name='Source Device'
    )
    destination_device = tables.Column(
        linkify=True,
        verbose_name='Destination Device'
    )
    source_ip_addr = tables.Column(
        linkify=True,
        verbose_name='Source IP'
    )
    destination_ip_addr = tables.Column(
        linkify=True,
        verbose_name='Destination IP'
    )

    destination_port = tables.Column(
        verbose_name='Destination Port'
    )
    network_protocol = tables.Column(
        verbose_name='Network Protocol'
    )
    transport_protocol = tables.Column(
        verbose_name='Transport Protocol'
    )
    application_protocol = tables.Column(
        verbose_name='Application Protocol'
    )


    class Meta(NetBoxTable.Meta):
        model = Communication
        fields = ('id', 'source_device', 'destination_device', 'source_ip_addr', 'destination_ip_addr', 'destination_port',
                  'network_protocol', 'transport_protocol', 'application_protocol')
        default_columns = ('id', 'source_device', 'destination_device', 'source_ip_addr', 'destination_ip_addr', 'destination_port',
                           'network_protocol', 'transport_protocol', 'application_protocol')


class CommunicationFindingTable(NetBoxTable):
    """
        Table for the CommunicationFinding model (Device specific).
    """
    class Meta(NetBoxTable.Meta):
        model = CommunicationFinding
        fields = ('id', 'source', 'source_ip', 'destination_ip', 'destination_port', 'network_protocol',
                  'transport_protocol', 'application_protocol', 'finding_status')
        default_columns = ('id', 'source', 'source_ip', 'destination_ip', 'destination_port', 'network_protocol',
                           'transport_protocol', 'application_protocol')


class UnassignedCommunicationFindingTable(NetBoxTable):
    """
        Table for the CommunicationFinding model (not Device specific).
    """
    actions = columns.ActionsColumn(
        actions=('edit',)
    )

    source_ip = tables.Column(verbose_name="Source IP")
    destination_ip = tables.Column(verbose_name="Destination IP")
    destination_port = tables.Column(verbose_name="Destination Port")
    network_protocol = tables.Column(verbose_name="Network Protocol")
    transport_protocol = tables.Column(verbose_name="Transport Protocol")
    application_protocol = tables.Column(verbose_name="Application Protocol")

    has_2_predicted_devices = columns.BooleanColumn(
        verbose_name="Has 2 predicted Devices"
    )

    predicted_src_device = tables.Column(
        linkify=True,
        verbose_name = "Predicted Source Device"
    )
    predicted_dst_device = tables.Column(
        linkify=True,
        verbose_name="Predicted Destination Device"
    )

    class Meta(NetBoxTable.Meta):
        model = CommunicationFinding
        fields = ('id', 'source', 'source_ip', 'destination_ip', 'destination_port', 'network_protocol',
                  'transport_protocol', 'application_protocol', 'finding_status', 'predicted_src_device',
                  'predicted_dst_device', 'has_2_predicted_devices')
        default_columns = ('id', 'source', 'source_ip', 'destination_ip', 'destination_port', 'network_protocol',
                           'transport_protocol', 'application_protocol', 'predicted_src_device', 'predicted_dst_device',
                           'has_2_predicted_devices')


class MappingTable(NetBoxTable):
    """
        Table for the Mapping model.
    """
    class Meta(NetBoxTable.Meta):
        model = Mapping
        fields = ('id', 'name', 'type', 'data')
        default_columns = ('id', 'type', 'name')
