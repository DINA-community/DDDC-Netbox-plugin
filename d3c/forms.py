"""
    This file provides all the input forms implemented by the D3C-Plugin.
"""

import csv
from .models import DeviceFinding, Software, Communication, \
    CommunicationFinding, Mapping, ProductRelationship, XGenericUri, Hash, FileHash, FILEHASH_ALGO
from .utils import parse_csv, parse_nmap, validate_cpe, validate_purl, validate_fh, validate_uri
from dcim.models.devices import Device, DeviceType
from ipam.models import IPAddress
from django import forms
from django.forms import ModelForm
from io import StringIO
from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm, NetBoxModelImportForm
from utilities.choices import ChoiceSet
from utilities.forms.fields import CommentField, DynamicModelChoiceField, DynamicModelMultipleChoiceField
from utilities.forms import BOOLEAN_WITH_BLANK_CHOICES
from xml.etree.ElementTree import ParseError
from django.contrib.postgres.forms import SimpleArrayField
from extras.models import CustomFieldChoiceSet
from django.core.exceptions import ObjectDoesNotExist
from netaddr import valid_mac, valid_ipv4


class HashForm(NetBoxModelForm):
    """
    Input Form for the Hash model.
    """
    class Meta:
        model = Hash
        fields = ('id', 'software', 'filename', 'tags')


class FileHashForm(NetBoxModelForm):
    """
    Input Form for the FilehHash model.
    """
    algorithm = forms.ChoiceField()

    value = forms.CharField(validators=[validate_fh,])

    class Meta:
        model = FileHash
        fields = ('id', 'hash', 'algorithm', 'value', 'tags')

    def __init__(self, *args, **kwargs):
        super(FileHashForm, self).__init__(*args, **kwargs)
        try:
            self.fields['algorithm'].choices = CustomFieldChoiceSet.objects.get(name='d3c_filehash_algo').extra_choices
        except ObjectDoesNotExist:
            self.fields['algorithm'].choices = FILEHASH_ALGO


class XGenericUriForm(NetBoxModelForm):
    """
    Input Form for the XGenericUri model.
    """
    devicetype = DynamicModelChoiceField(
        queryset=DeviceType.objects.all(),
        required=False,
        selector=True,
        label='Device Type'
    )
    software = DynamicModelChoiceField(
        queryset=Software.objects.all(),
        required=False,
        selector=True,
    )
    namespace = forms.CharField(required=True, label="Namespace", validators=[validate_uri])

    uri = forms.CharField(required=True, label="Uri", validators=[validate_uri])

    class Meta:
        model = XGenericUri
        fields = [
            'namespace', 'uri', 'tags'
        ]

    def __init__(self, *args, **kwargs):

        # Initialize helper selectors
        instance = kwargs.get('instance')
        initial = kwargs.get('initial', {}).copy()
        if instance:
            if type(instance.content_object) is DeviceType:
                initial['devicetype'] = instance.content_object
            elif type(instance.content_object) is Software:
                initial['software'] = instance.content_object
        kwargs['initial'] = initial

        super().__init__(*args, **kwargs)

    def clean(self):
        super().clean()

        # Handle object assignment
        selected_objects = [
            field for field in ('devicetype', 'software') if self.cleaned_data[field]
        ]
        if len(selected_objects) > 1:
            raise forms.ValidationError(
               "A XGenericUri can only be assigned to a single parent object."
            )
        elif selected_objects:
            assigned_object = self.cleaned_data[selected_objects[0]]
            self.instance.content_object = assigned_object
        else:
            raise forms.ValidationError(
                "A XGenericUri needs a parent object."
            )


class ProductRelationshipForm(NetBoxModelForm):
    """
    Input Form for the ProductRelationship model.
    """
    source_device = DynamicModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        selector=True,
        label='Parent device*'
    )
    source_software = DynamicModelChoiceField(
        queryset=Software.objects.all(),
        required=False,
        selector=True,
        label='Parent software*'
    )
    destination_device = DynamicModelChoiceField(
        queryset=Device.objects.all(),
        required=False,
        selector=True,
        label='Target device*'
    )
    destination_software = DynamicModelChoiceField(
        queryset=Software.objects.all(),
        required=False,
        selector=True,
        label='Target software*'
    )

    class Meta:
        model = ProductRelationship
        fields = [
            'category', 'tags'
        ]

    def __init__(self, *args, **kwargs):

        # Initialize helper selectors
        instance = kwargs.get('instance')
        initial = kwargs.get('initial', {}).copy()
        if instance:
            if type(instance.source) is Device:
                initial['source_device'] = instance.source
            elif type(instance.source) is Software:
                initial['source_software'] = instance.source

            if type(instance.destination) is Device:
                initial['destination_device'] = instance.destination
            elif type(instance.destination) is Software:
                initial['destination_software'] = instance.destination
        kwargs['initial'] = initial

        super().__init__(*args, **kwargs)

    def clean(self):
        super().clean()

        source_selected_objects = [
            field for field in ('source_device', 'source_software') if self.cleaned_data[field]
        ]
        if len(source_selected_objects) > 1:
            raise forms.ValidationError("A ProductRelationship can only be assigned to a single parent object.")
        elif source_selected_objects:
            assigned_object = self.cleaned_data[source_selected_objects[0]]
            self.instance.source = assigned_object
        else:
            raise forms.ValidationError("A ProductRelationship needs a parent object.")

        destination_selected_objects = [
            field for field in ('destination_device', 'destination_software') if self.cleaned_data[field]
        ]
        if len(destination_selected_objects) > 1:
            raise forms.ValidationError("A ProductRelationship can only be assigned to a single destination object.")
        elif destination_selected_objects:
            assigned_object = self.cleaned_data[destination_selected_objects[0]]
            self.instance.destination = assigned_object
        else:
            raise forms.ValidationError("A ProductRelationship needs a destination object.")



class DeviceFindingForm(NetBoxModelForm):
    """
    Input Form for the DeviceFinding model.
    """
    confidence = forms.DecimalField(
        max_value=1,
        min_value=0,
        required=False,
    )

    ip_address = forms.CharField(required=False, label='IP Address', help_text='Specify at least the IP or MAC address.')

    mac_address = forms.CharField(required=False, label='MAC Address', help_text='Specify at least the IP or MAC address.')

    class Meta:
        model = DeviceFinding
        fields = ('id', 'source', 'confidence', 'ip_address', 'ip_netmask', 'mac_address',
                  'device_role', 'serial_number', 'device_name', 'status', 'site', 'rack', 'location',
                  'description', 'device_type', 'serial_number', 'device_role', 'is_safety_critical',
                  'network_protocol', 'transport_protocol', 'application_protocol', 'port',
                  'is_router', 'manufacturer', 'device_family', 'article_number', 'part_number',
                  'hardware_version', 'hardware_cpe', 'software_name', 'is_firmware', 'version',
                  'exposure', 'finding_status')

    def clean(self):
        cleaned_data = super().clean()
        if not self.cleaned_data.get('ip_address') and not self.cleaned_data.get('mac_address'):
            raise forms.ValidationError({'ip_address': 'Even one of IP Address or MAC Address should have a value.'})


class DeviceFindingCreateDeviceForm(forms.Form):
    """
    Input Form for the DeviceFinding model.
    """
    title = "Create Device based on DeviceFinding"

    device_name = forms.CharField(required=True)

    interface_name = forms.CharField(required=True,
                                     help_text='Creates a new interface using the provided name, and assign the IP and '
                                               'MAC addresses provided by the Finding.')
    comments = CommentField()

    def clean_device_name(self):
        data = self.cleaned_data['device_name']
        if Device.objects.filter(name=data).exists():
            raise forms.ValidationError('Device name already in use')
        return data


class DeviceFindingApplyForm(forms.Form):
    """
    Input Form for the ApplyFinding functionality of a single DeviceFinding.
    """
    title = "Edit Device based on DeviceFinding"

    device_name = forms.ChoiceField(
        initial='0',
        required=False,
        label="Name",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_description = forms.ChoiceField(
        initial='0',
        required=False,
        label="Device Description",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    manufacturer = forms.ChoiceField(
        initial='0',
        required=False,
        label="Manufacturer",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_type = forms.ChoiceField(
        initial='0',
        required=False,
        label="Device Type",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_family = forms.ChoiceField(
        initial='0',
        required=False,
        label="Device Family",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_role = forms.ChoiceField(
        initial='0',
        required=False,
        label="Device Role",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_article = forms.ChoiceField(
        initial='0',
        required=False,
        label="Article Number",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_model = forms.ChoiceField(
        initial='0',
        required=False,
        label="Part Number",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_serial = forms.ChoiceField(
        initial='0',
        required=False,
        label="Serial Number",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_status = forms.ChoiceField(
        initial='0',
        required=False,
        label="Status",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_exposure = forms.ChoiceField(
        initial='0',
        required=False,
        label="Exposure",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_site = forms.ChoiceField(
        initial='0',
        required=False,
        label="Site",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_rack = forms.ChoiceField(
        initial='0',
        required=False,
        label="Rack",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_location = forms.ChoiceField(
        initial='0',
        required=False,
        label="Location",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_safety = forms.ChoiceField(
        initial='0',
        required=False,
        label="Is safety crucial",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_hver = forms.ChoiceField(
        initial='0',
        required=False,
        label="Hardware Version",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_hcpe = forms.ChoiceField(
        initial='0',
        required=False,
        label="Hardware CPE",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    device_router = forms.ChoiceField(
        initial='0',
        required=False,
        label="Is router interface",
        widget=forms.RadioSelect(attrs={'class': 'col-sm-3 btn-check form-control'})
    )

    add_service = forms.BooleanField(
        required=False,
        help_text='Automatically populate/add this service'
    )

    add_software = forms.BooleanField(
        required=False,
        help_text='Automatically populate/add software to device'
    )

    def __init__(self, *args, **kwargs):
        manufacturer_choices = kwargs.pop('manu_c', None)
        device_type_choices = kwargs.pop('type_c', None)
        device_role_choices = kwargs.pop('role_c', None)
        device_name_choices = kwargs.pop('name_c', None)
        device_family_choices = kwargs.pop('family_c', None)
        device_description_choices = kwargs.pop('description_c', None)
        device_article_choices = kwargs.pop('article_c', None)
        device_model_choices = kwargs.pop('model_c', None)
        device_serial_choices = kwargs.pop('serial_c', None)
        device_status_choices = kwargs.pop('status_c', None)
        device_exposure_choices = kwargs.pop('exposure_c', None)
        device_site_choices = kwargs.pop('site_c', None)
        device_rack_choices = kwargs.pop('rack_c', None)
        device_location_choices = kwargs.pop('location_c', None)
        device_safety_choices = kwargs.pop('safety_c', None)
        device_hver_choices = kwargs.pop('hver_c', None)
        device_hcpe_choices = kwargs.pop('hcpe_c', None)
        device_router_choices = kwargs.pop('router_c', None)
        super(DeviceFindingApplyForm, self).__init__(*args, **kwargs)
        if manufacturer_choices:
            self.fields['manufacturer'].choices = manufacturer_choices
        if device_type_choices:
            self.fields['device_type'].choices = device_type_choices
        if device_role_choices:
            self.fields['device_role'].choices = device_role_choices
        if device_name_choices:
            self.fields['device_name'].choices = device_name_choices
        if device_family_choices:
            self.fields['device_family'].choices = device_family_choices
        if device_description_choices:
            self.fields['device_description'].choices = device_description_choices
        if device_article_choices:
            self.fields['device_article'].choices = device_article_choices
        if device_model_choices:
            self.fields['device_model'].choices = device_model_choices
        if device_serial_choices:
            self.fields['device_serial'].choices = device_serial_choices
        if device_status_choices:
            self.fields['device_status'].choices = device_status_choices
        if device_exposure_choices:
            self.fields['device_exposure'].choices = device_exposure_choices
        if device_site_choices:
            self.fields['device_site'].choices = device_site_choices
        if device_rack_choices:
            self.fields['device_rack'].choices = device_rack_choices
        if device_location_choices:
            self.fields['device_location'].choices = device_location_choices
        if device_safety_choices:
            self.fields['device_safety'].choices = device_safety_choices
        if device_hver_choices:
            self.fields['device_hver'].choices = device_hver_choices
        if device_hcpe_choices:
            self.fields['device_hcpe'].choices = device_hcpe_choices
        if device_router_choices:
            self.fields['device_router'].choices = device_router_choices



class DeviceFindingEditForm(NetBoxModelForm):
    """
    Input Form for editing a DeviceFinding.
    """
    device = DynamicModelChoiceField(
        required=False,
        queryset=Device.objects.all(),
        null_option="None",
        help_text='Select the device for which the interface should be created or adapted.'
    )
    interface_name = forms.CharField(required=False,
                                     help_text='If the interface does not exist with this name, it is created. '
                                               'If it does exist, the MAC is updated if not already set, and if it is '
                                               'set, a new IP is created using the Finding\'s IP and assigned to the '
                                               'interface.')

    class Meta:
        model = DeviceFinding
        fields = ('id', 'device', 'interface_name', 'ip_address', 'ip_netmask', 'mac_address')

    def clean_ip_address(self):
        if self.cleaned_data['ip_address']:
            ip_list = [valid_ipv4(ip.strip()) for ip in self.cleaned_data['ip_address'].split(',')]
            if False in ip_list:
                raise forms.ValidationError('Invalid IP Address')
        return self.cleaned_data['ip_address']

    def clean_mac_address(self):
        if self.cleaned_data['mac_address']:
            mac_list = [valid_mac(mac.strip()) for mac in self.cleaned_data['mac_address'].split(',')]
            if False in mac_list:
                raise forms.ValidationError('Invalid MAC Address')
        return self.cleaned_data['mac_address']


class DeviceFindingFilterForm(NetBoxModelFilterSetForm):
    """
    Input Form for filtering a DeviceFinding.
    """
    model = DeviceFinding

    source = forms.CharField(required=False)
    has_predicted_device = forms.NullBooleanField(
        required=False,
        widget=forms.Select(
            choices=BOOLEAN_WITH_BLANK_CHOICES
        )
    )

    confidence = forms.CharField(required=False)
    manufacturer = forms.CharField(required=False)
    device_role = forms.CharField(required=False)
    device_type = forms.CharField(required=False)
    ip_address = forms.CharField(required=False)
    mac_address = forms.CharField(required=False)
    network_protocol = forms.CharField(required=False)
    transport_protocol = forms.CharField(required=False)
    application_protocol = forms.CharField(required=False)
    port = forms.CharField(required=False)


class ImportFormatChoices(ChoiceSet):
    CSV = 'csv'
    NMAP = 'nmap'

    CHOICES = [
        (CSV, 'CSV'),
        (NMAP, 'NMap'),
    ]


class FindingImportForm(forms.Form):
    """Form for importing DeviceFindings"""

    title = "Importing DeviceFindings"
    fieldNames = ('source', 'confidence',
                  'description', 'device_role', 'serial_number', 'device_name', 'status', 'site', 'rack', 'location',
                  'device_type', 'serial_number', 'device_role', 'is_safety_critical',
                  'ip_address', 'ip_netmask', 'mac_address', 'network_protocol', 'transport_protocol', 'application_protocol', 'port',
                  'is_router', 'manufacturer', 'oui', 'device_family', 'article_number', 'part_number',
                  'hardware_version', 'hardware_cpe', 'software_name', 'is_firmware', 'version', 'exposure')
    templates = {}
    csv_headers = {}
    csv_records = []

    step = 0
    step_field = forms.IntegerField(widget=forms.HiddenInput(), initial=1)
    file_name = forms.CharField(widget=forms.HiddenInput(), initial='')
    data_string = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'font-monospace form-control',
            'style': 'width: 100%;height:10em'}),
        label="Raw Data",
        required=False
    )
    data_file = forms.FileField(
        label="Data file",
        required=False
    )
    format = forms.ChoiceField(
        choices=ImportFormatChoices,
        initial=ImportFormatChoices.CSV,
        widget=forms.Select(
            attrs={'class': 'form-control'}
        )
    )
    mapping = DynamicModelChoiceField(
        queryset=Mapping.objects.all(),
        required=False
    )
    mapping_name = forms.fields.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={'class': 'form-control'}
        )
    )
    submit_button = forms.CharField()

    def __init__(self, data=None, files=None, initial=None):
        super().__init__(data=data, files=files, initial=initial)
        for name in self.fieldNames:
            fieldName = name
            field = forms.fields.CharField(
                required=False,
                widget=forms.TextInput(
                    attrs={'class': 'form-control'}
                )
            )
            findingField = getattr(DeviceFinding, name)
            if findingField.field.verbose_name != name:
                field.label = findingField.field.verbose_name
            self.fields[fieldName] = field
            self.templates[name] = fieldName
        self.fields['source'].required = False

    def clean(self):
        super().clean()
        data = self.cleaned_data['data_string']
        self.step = self.cleaned_data['step_field']
        file = self.files.get('data_file')
        if file:
            filedata = file.read().decode('utf-8-sig')
            if filedata:
                data = filedata
                self.cleaned_data['data_string'] = filedata
                self.cleaned_data['file_name'] = file.name
        if not data:
            raise forms.ValidationError(f"Data must be supplied either directly, or as file.")

        format = self.cleaned_data['format']
        if format == ImportFormatChoices.CSV:
            self._clean_csv(data)
        elif format == ImportFormatChoices.NMAP:
            self._clean_nmap(data)
        else:
            raise forms.ValidationError(f"Unknown data format: {format}")

        if self.cleaned_data.get('submit_button') == 'mapping_save' and not self.cleaned_data.get('mapping_name'):
            raise forms.ValidationError("Mapping Name must be supplied when saving a mapping.", code="invalid")

        if self.cleaned_data.get('submit_button') in ['mapping_load', 'mapping_delete'] and not self.cleaned_data.get('mapping'):
            raise forms.ValidationError("A Mapping must be selected when loading or deleting mapping.", code="invalid")

    def writeData(self, headers, data):
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(headers.keys())
        for record in data:
            row = []
            for name in headers.keys():
                row.append(record.get(name, ''))
            writer.writerow(row)
        self.cleaned_data['data_string'] = output.getvalue()
        self.cleaned_data['format'] = ImportFormatChoices.CSV

    def _clean_nmap(self, data):
        """
        Clean NMAP-XML-formatted data.
        """
        try:
            headers, records = parse_nmap(data.strip())
        except ParseError:
            raise forms.ValidationError("Data is not XML.", code="invalid")

        # Set CSV headers for reference by the model form
        self.csv_headers = headers
        self.csv_records = records

        emptyHeaders = headers.copy()
        filledHeaders = {}
        for record in records:
            for header in list(emptyHeaders.keys()):
                if record.get(header):
                    filledHeaders[header] = emptyHeaders.pop(header)
            if not emptyHeaders:
                break
        self.csv_headers_filled = filledHeaders
        self.csv_headers_empty = emptyHeaders

        return records

    def _clean_csv(self, data):
        """
        Clean CSV-formatted data. The first row will be treated as column headers.
        """
        stream = StringIO(data.strip())
        reader = csv.reader(stream)
        headers, records = parse_csv(reader)

        # Set CSV headers for reference by the model form
        self.csv_headers = headers
        self.csv_records = records

        emptyHeaders = headers.copy()
        filledHeaders = {}
        for record in records:
            for header in list(emptyHeaders.keys()):
                if record.get(header):
                    filledHeaders[header] = emptyHeaders.pop(header)
            if not emptyHeaders:
                break
        self.csv_headers_filled = filledHeaders
        self.csv_headers_empty = emptyHeaders

        return records


class SoftwareForm(NetBoxModelForm):
    """
    Input Form for the Software model.
    """
    cpe = forms.CharField(required=False, label="CPE", validators=[validate_cpe])

    purl = forms.CharField(required=False, label="PURL", validators=[validate_purl])

    sbom_urls = SimpleArrayField(
        label='SBOM URLs',
        base_field=forms.URLField(),
        required=False,
        help_text='Comma-separated list of one or more sbom urls.'
    )

    class Meta:
        model = Software
        fields = ('id', 'name', 'is_firmware', 'version', 'cpe', 'purl', 'sbom_urls',  'tags')


class SoftwareFilterForm(NetBoxModelFilterSetForm):
    """
    Input Form for filtering Software objects.
    """
    model = Software
    devices = DynamicModelMultipleChoiceField(
        queryset=Device.objects.all(),
        required=False
    )
    name = forms.CharField(required=False)
    is_firmware = forms.BooleanField(required=False)
    cpe = forms.CharField(required=False)
    version = forms.CharField(required=False)


class SoftwareImportForm(ModelForm):
    """Form for importing Software"""

    title = "Importing Software."
    csvdata = forms.CharField(widget=forms.Textarea)

    class Meta:
        model = Software
        fields = ('name', 'is_firmware', 'version', 'cpe', 'purl', 'sbom_urls')


####
class CommunicationForm(NetBoxModelForm):
    """
    Input Form for Communications.
    """
    # source_device = DynamicModelChoiceField(
    #     queryset=Device.objects.all(),
    # )
    source_ip_addr = DynamicModelChoiceField(
        queryset=IPAddress.objects.all(),
    )
    destination_ip_addr = DynamicModelChoiceField(
        queryset=IPAddress.objects.all(),
    )

    class Meta:
        model = Communication
        fields = ('id', 'source_ip_addr', 'destination_ip_addr', 'destination_port',
                  'network_protocol', 'transport_protocol', 'application_protocol')


class CommunicationFilterForm(NetBoxModelFilterSetForm):
    """
    Input Form for filtering Communications.
    """
    model = Communication
    # source_device = DynamicModelMultipleChoiceField(
    #     queryset=Device.objects.all(),
    #     required=False
    # )
    source_ip_addr = DynamicModelChoiceField(
        queryset=IPAddress.objects.all(),
        required=False
    )
    destination_ip_addr = DynamicModelChoiceField(
        queryset=IPAddress.objects.all(),
        required=False
    )
    destination_port = forms.IntegerField(required=False)
    network_protocol = forms.CharField(required=False)
    transport_protocol = forms.CharField(required=False)
    application_protocol = forms.CharField(required=False)


class CommunicationImportForm(NetBoxModelImportForm):
    """Form for importing Communication"""

    title = "Importing Communication."
#    csvdata = forms.CharField(widget=forms.Textarea)

    class Meta:
        model = Communication
        fields = ('source_device', 'destination_device', 'source_ip_addr', 'destination_ip_addr', 'destination_port',
                  'network_protocol', 'transport_protocol', 'application_protocol')



#######

class CommunicationFindingForm(NetBoxModelForm):
    """
    Input Form for CommunicationFinding.
    """
    class Meta:
        model = CommunicationFinding
        fields = ('id', 'source', 'source_ip', 'destination_ip', 'destination_port', 'network_protocol',
                  'transport_protocol', 'application_protocol', 'finding_status')


class CommunicationFindingFilterForm(NetBoxModelFilterSetForm):
    """
    Input Form for filtering CommunicationFindings.
    """
    model = CommunicationFinding
    source = forms.CharField(required=False)
    source_ip = forms.CharField(required=False)
    destination_ip = forms.CharField(required=False)
    destination_port = forms.CharField(required=False)
    network_protocol = forms.CharField(required=False)
    transport_protocol = forms.CharField(required=False)
    application_protocol = forms.CharField(required=False)
    predicted_src_device = forms.CharField(required=False)
    predicted_dst_device = forms.CharField(required=False)
    has_2_predicted_devices = forms.NullBooleanField(
        required=False,
        widget=forms.Select(
            choices=BOOLEAN_WITH_BLANK_CHOICES
        )
    )


class CommunicationFindingImportForm(NetBoxModelImportForm):
    """Form for importing CommunicationFindings"""

    title = "Importing CommunicationFinding."

    class Meta:
        model = CommunicationFinding
        fields = ('id', 'source', 'source_ip', 'destination_ip', 'destination_port', 'network_protocol',
                  'transport_protocol', 'application_protocol')


class DeviceFindingImportForm(NetBoxModelImportForm):
    """Form for importing DeviceFindings"""

    class Meta:
        model = DeviceFinding
        fields = ('id', 'device', 'source', 'confidence',
                  'description', 'device_role', 'serial_number', 'device_name', 'status', 'site', 'rack', 'location',
                  'device_type', 'serial_number', 'device_role', 'is_safety_critical',
                  'ip_address', 'ip_netmask', 'mac_address', 'network_protocol', 'transport_protocol', 'application_protocol', 'port',
                  'is_router', 'manufacturer', 'oui', 'device_family', 'article_number', 'part_number',
                  'hardware_version', 'hardware_cpe', 'software_name', 'is_firmware', 'version', 'exposure',)


class CommunicationFindingEditForm(NetBoxModelForm):
    """Form for editing CommunicationFindings"""
    # src_device = DynamicModelChoiceField(
    #     queryset=Device.objects.all(),
    #     null_option="None",
    #     required=False
    # )
    # dst_device = DynamicModelChoiceField(
    #     queryset=Device.objects.all(),
    #     null_option="None",
    #     required=False
    # )

    class Meta:
        model = CommunicationFinding
        fields = ('id', 'source_ip', 'destination_ip', 'destination_port', 'network_protocol', 'transport_protocol', 'application_protocol')


# Mapping Forms
class MappingForm(NetBoxModelForm):
    """Input Form for the Mapping model."""
    class Meta:
        model = Mapping
        fields = ('id', 'type', 'name', 'data')


class MappingFilterForm(NetBoxModelFilterSetForm):
    """Form for filtering Mappings."""
    model = Mapping
