import json
import logging
from dcim.models import Device, DeviceRole, Site
from dcim.tables.devices import DeviceTable
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.db import transaction, IntegrityError
from django.forms.utils import pretty_name
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.utils.html import escape
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django.views.generic.edit import FormView
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from core.signals import clear_events
from netbox.views import generic
from netbox.views.generic.base import BaseMultiObjectView
from netbox.views.generic.mixins import TableMixin
from netbox.views.generic.utils import get_prerequisite_model
from utilities.exceptions import AbortRequest, AbortTransaction, PermissionsViolation
from utilities.forms import restrict_form_fields
from utilities.htmx import htmx_partial
from utilities.querydict import normalize_querydict
from utilities.views import ViewTab, register_model_view
from utilities.views import GetReturnURLMixin
from .device_update import *
from .string_checker import StringChecker
from .string_helper import get_sug, init_spell_checker
from .string_miner import StringMiner
from .string_normalizer import StringNormalizer
from .utils import fillTemplate, get_ip, get_mac, time_start, time_end
from . import filtersets, forms, models, tables
import re
from netaddr import valid_mac, valid_ipv4


# Four StringChecker modules are created, each one for the attributes
# Manufacturer, Device Family, Device Type, and Article Number.
S_CHECKER = {
    'manufacturer': init_spell_checker(["Manufacturer"], ["Manufacturer"], None),
    'device_family': init_spell_checker(["Device Family"], None, None),
    'device_type': init_spell_checker(["Device Type"], ["Device Type"], None),
    'article_number': init_spell_checker(["Article Number"], None, None)
}

S_NORMALIZER = StringNormalizer()


@register_model_view(models.FileHash, 'edit')
class FileHashEditView(generic.ObjectEditView):
    """ This view handles the edit requests for the FileHash model. """
    queryset = models.FileHash.objects.all()
    form = forms.FileHashForm


class FileHashDeleteView(generic.ObjectDeleteView):
    """ This view handles the delete requests for the FileHash model. """
    queryset = models.FileHash.objects.all()


class FileHashView(generic.ObjectView):
    """ This view handles the request for displaying a FileHash. """
    queryset = models.FileHash.objects.all()


class FileHashListView(generic.ObjectListView):
    """ This view handles the request for displaying multiple FileHashes as a table. """
    queryset = models.FileHash.objects.all()
    table = tables.FileHashTable


@register_model_view(models.Hash, 'edit')
class HashEditView(generic.ObjectEditView):
    """ This view handles the edit requests for the Hash model. """
    queryset = models.Hash.objects.all()
    form = forms.HashForm


class HashDeleteView(generic.ObjectDeleteView):
    """ This view handles the delete requests for the Hash model. """
    queryset = models.Hash.objects.all()


class HashView(generic.ObjectView):
    """ This view handles the request for displaying a single Hash. """
    queryset = models.Hash.objects.all()


class HashListView(generic.ObjectListView):
    """ This view handles the request for displaying multiple Hashes as a table. """
    queryset = models.Hash.objects.all()
    table = tables.HashTable


class XGenericUriDeleteView(generic.ObjectDeleteView):
    """ This view handles the delete requests for the XGenericUri model. """
    queryset = models.XGenericUri.objects.all()


class XGenericUriView(generic.ObjectView):
    """ This view handles the request for displaying a single XGenericUri. """
    queryset = models.XGenericUri.objects.all()


class XGenericUriListView(generic.ObjectListView):
    """ This view handles the request for displaying multiple XGenericUris as a table. """
    queryset = models.XGenericUri.objects.all()
    table = tables.XGenericUriTable


@register_model_view(models.XGenericUri, 'edit')
class XGenericUriEditView(generic.ObjectEditView):
    """ This view handles the request for editing the XGenericUri model. """
    queryset = models.XGenericUri.objects.all()
    form = forms.XGenericUriForm
    template_name = 'd3c/xgenericuri_edit.html'

    def alter_object(self, obj, request, url_args, url_kwargs):
        if 'devicetype' in request.GET:
            try:
                obj.parent = DeviceType.objects.get(pk=request.GET['devicetype'])
            except (ValueError, DeviceType.DoesNotExist):
                pass
        elif 'software' in request.GET:
            try:
                obj.parent = models.Software.objects.get(pk=request.GET['software'])
            except (ValueError, models.Software.DoesNotExist):
                pass
        return obj


class ProductRelationshipDeleteView(generic.ObjectDeleteView):
    """ This view handles the delete requests for the ProductRelationship model. """
    queryset = models.ProductRelationship.objects.all()


class ProductRelationshipView(generic.ObjectView):
    """ This view handles the request for displaying a single ProductRelationship. """
    queryset = models.ProductRelationship.objects.all()


class ProductRelationshipListView(generic.ObjectListView):
    """ This view handles the request for displaying multiple ProductRelationships as a table. """
    queryset = models.ProductRelationship.objects.all()
    table = tables.ProductRelationshipTable
    #template_name = 'd3c/object_list_custom.html'


@register_model_view(models.ProductRelationship, 'edit')
class ProductRelationshipEditView(generic.ObjectEditView):
    """ This view handles the request for editing the ProductRelationship model. """
    queryset = models.ProductRelationship.objects.all()
    form = forms.ProductRelationshipForm
    template_name = 'd3c/productrelationship_edit.html'

    def alter_object(self, obj, request, url_args, url_kwargs):
        if 'device' in request.GET:
            try:
                obj.parent = Device.objects.get(pk=request.GET['device'])
            except (ValueError, Device.DoesNotExist):
                pass
        elif 'software' in request.GET:
            try:
                obj.parent = models.Software.objects.get(pk=request.GET['software'])
            except (ValueError, models.Software.DoesNotExist):
                pass
        return obj


class DeviceFindingView(generic.ObjectView):
    """ This view handles the request for displaying a single DeviceFinding. """
    queryset = models.DeviceFinding.objects.all()


class DeviceFindingListView(generic.ObjectListView):
    """ This view handles the request for displaying multiple DeviceFindings as a table. """
    queryset = models.DeviceFinding.objects.filter(device__isnull=True).filter(finding_status="NEW")
    table = tables.UnassignedDeviceFindingTable
    filterset = filtersets.DeviceFindingFilterSet
    filterset_form = forms.DeviceFindingFilterForm
    template_name = 'd3c/devicefinding_list.html'
    actions = {
        'add': {'add'},
        'edit': {'change'},
        'export': set(),
        'bulk_sync': {'sync'}}


class DeviceFindingMap(GetReturnURLMixin, BaseMultiObjectView):
    """ This view handles the request for mapping DeviceFindings. """
    queryset = models.DeviceFinding.objects.all()

    def get_required_permission(self):
        return '{}.{}_{}'.format('d3c', 'edit', 'DeviceFinding')

    def post(self, request):
        selected_objects = self.queryset.filter(
            pk__in=request.POST.getlist('pk'),
        )

        with transaction.atomic():
            count = 0
            for device_finding in selected_objects:
                if device_finding.device:
                    device_finding.save()
                    count += 1
                elif device_finding.has_predicted_device:
                    device = device_finding.get_matched_device()
                    if device:
                        device_finding.device = device
                        device_finding.save()
                        count += 1
                else:
                    messages.error(request, f"Mapping of record with ID {device_finding.pk} not possible.")

            model_name = self.queryset.model._meta.verbose_name_plural
            if count > 0:
                messages.success(request, f"Mapped {count} {model_name}")

        return redirect(self.get_return_url(request))


class DeviceFindingReject(GetReturnURLMixin, BaseMultiObjectView):
    """ This view handles the request for rejecting DeviceFindings. """
    queryset = models.DeviceFinding.objects.all()

    def get_required_permission(self):
        return '{}.{}_{}'.format('d3c', 'edit', 'DeviceFinding')

    def post(self, request):
        selected_objects = self.queryset.filter(
            pk__in=request.POST.getlist('pk'),
        )

        with transaction.atomic():
            count = 0
            for device_finding in selected_objects:
                device_finding.finding_status = "REJECT"
                device_finding.save()
                count += 1

            model_name = self.queryset.model._meta.verbose_name_plural
            if count > 0:
                messages.success(request, f"{count} {model_name} rejected")

        return redirect(self.get_return_url(request))


class DeviceFindingSplit(GetReturnURLMixin, BaseMultiObjectView):
    """ This view handles the request for splitting DeviceFindings w.r.t. IP and MAC Addresses. """
    queryset = models.DeviceFinding.objects.all()

    def get_required_permission(self):
        return '{}.{}_{}'.format('d3c', 'edit', 'DeviceFinding')

    def post(self, request):
        selected_objects = self.queryset.filter(
            pk__in=request.POST.getlist('pk'),
        )

        with transaction.atomic():
            processed_counter = 0
            failed_counter = 0
            for df in selected_objects:
                if "," in df.ip_address or "," in df.mac_address:
                    processed_counter += 1
                    ips = [ip.strip() for ip in df.ip_address.split(',')]
                    macs = [mac.strip() for mac in df.mac_address.split(',')]
                    valid_ips = [valid_ipv4(ip) for ip in ips]
                    valid_macs = [valid_mac(mac) for mac in macs]
                    if len(ips) == len(macs) and False not in (valid_ips or valid_macs) and len(ips) <= 10:
                        for idx in range(len(ips)):
                            obj = models.DeviceFinding.objects.get(pk=df.pk)
                            obj.pk = None
                            obj.ip_address = ips[idx]
                            obj.mac_address = macs[idx]
                            obj.finding_status = "NEW"
                            obj.has_predicted_device = False
                            obj.predicted_device = None
                            obj.device = None
                            obj.save()
                        df.finding_status = "REJECT"
                        df.save()
                    else:
                        failed_counter += 1


            if failed_counter == 0:
                messages.success(request, f"{processed_counter} DeviceFinding(s) split")
            else:
                msg = f"Split failed for {failed_counter} out of {processed_counter} DeviceFinding(s)"
                messages.error(request, msg)

        return redirect(self.get_return_url(request))


class DeviceFindingLookupView(View):
    """ This view handles the request for performing the Device Lookup. """
    def get(self, request, *args, **kwargs):
        with transaction.atomic():
            result = models.df_device_lookup()
            if result:
                messages.success(request, f"Device Lookup finished")
            else:
                messages.error(request, f"Exception occurred while lookup")

        return redirect(reverse('plugins:d3c:devicefinding_list'))


@register_model_view(Device, name='findinglistfordeviceview', path='findings')
class FindingListForDeviceView(View, TableMixin):
    """ This view handles the request for displaying the Findings-Tab within the Detail-View of a Device. """
    base_template = 'dcim/device.html'
    template_name = 'd3c/findings_for_device.html'
    table = tables.DeviceFindingForDeviceTable
    actions = ()

    tab = ViewTab(
        label='Findings',
        badge=lambda obj: models.DeviceFinding.objects.filter(device=obj, finding_status='NEW').count(),
        permission='findings.view_stuff'
    )

    def hideEmptyColumns(self, data, table):
        for fieldName, column in table.base_columns.items():
            empty = True
            for finding in data:
                if getattr(finding, fieldName, 'non-data-field'):
                    empty = False
                    break
            if empty:
                table.columns.hide(fieldName)
        columns = table.columns.columns
        if not columns['network_protocol'].visible and not columns['transport_protocol'].visible and not columns['application_protocol'].visible and not columns['port'].visible:
            table.columns.hide('service')
        if not columns['software_name'].visible and not columns['is_firmware'].visible and not columns['version'].visible:
            table.columns.hide('software')

    def get(self, request, **kwargs):
        #time_start('get')
        self.device = get_object_or_404(Device, **kwargs)
        self.queryset = models.DeviceFinding.objects.filter(device=self.kwargs["pk"])
        requestedStatus = request.GET.get('finding_status', 'NEW')
        if requestedStatus != 'ALL':
            self.queryset = self.queryset.filter(finding_status=requestedStatus)
        requestedSpelchecker = request.GET.get('spelchecker', '0')
        table = self.get_table(self.queryset, request, False)
        table.setStringNormalizerEnabled(True)
        table.setDevice(self.device)
        if requestedSpelchecker == '1':
            table.setStringCheckerEnabled(True)

        self.hideEmptyColumns(table.data, table)
        #time_end()

        if htmx_partial(request):
            return render(request, 'htmx/table.html', {
                'object': self.device,
                'table': table,
                'base_template': self.base_template,
                'tab': self.tab,
                'actions': self.actions,
                'model': self.queryset.model,
                'requestedStatus': requestedStatus,
                'requestedSpelchecker': requestedSpelchecker,
                'prerequisite_model': get_prerequisite_model(self.queryset),
            })

        return render(request, self.template_name, {
            'object': self.device,
            'table': table,
            'base_template': self.base_template,
            'tab': self.tab,
            'actions': self.actions,
            'model': self.queryset.model,
            'requestedStatus': requestedStatus,
            'requestedSpelchecker': requestedSpelchecker,
            'prerequisite_model': get_prerequisite_model(self.queryset),
        })

    def getFromPost(self, data, name, id):
        return data.get(name+'-'+str(id))

    def post(self, request, *args, **kwargs):
        logger = logging.getLogger('d3c.views.FindingListForDeviceView')
        self.device = get_object_or_404(Device, **kwargs)
        data = request.POST

        findingIds = []
        groupsData = {}
        for groupName in self.table.groupedFields:
            groupsData[groupName] = []
        for postName, postValue in data.items():
            for groupName, groupDef in self.table.groupedFields.items():
                if postName.startswith(groupName + '-'):
                    findingId = postName[len(groupName)+1:]
                    groupData = {'findingId': findingId}
                    for fieldName in groupDef.get('columns'):
                        groupData[fieldName] = self.getFromPost(data, fieldName, findingId)
                    groupsData[groupName].append(groupData)
            if postName.startswith('id-'):
                findingId = int(postName[3:])
                findingIds.append(findingId)

        device_type = data.get('device_type', None)
        manufacturer = data.get('manufacturer', None)
        device_description = data.get('description', None)
        device_name = data.get('device_name', None)
        device_family = data.get('device_family', None)
        device_role = data.get('device_role', None)
        article_number = data.get('article_number', None)
        model_number = data.get('part_number', None)
        serial_number = data.get('serial_number', None)
        device_status = data.get('status', None)
        device_exposure = data.get('exposure', None)
        device_site = data.get('site', None)
        device_rack = data.get('rack', None)
        device_location = data.get('location', None)
        device_safety = data.get('is_safety_critical', None)
        device_hver = data.get('hardware_version', None)
        device_hcpe = data.get('hardware_cpe', None)

        result_device = True
        result_role = True
        result_service = True
        result_software = True
        if not device_type and manufacturer:
            result_device = change_manufacturer_of_device_type(self.device, manufacturer)
        elif device_type and not manufacturer:
            result_device = change_device_type_keep_manufacturer(self.device, device_type)
        elif device_type and manufacturer:
            result_device = change_device_type_and_manufacturer(self.device, device_type, manufacturer)

        if device_description:
            result_device &= change_device_description(self.device, device_description)
        if device_name:
            result_device &= change_device_name(self.device, device_name)
        if device_family:
            result_device &= change_device_family(self.device, device_family)
        if device_role:
            result_role &= change_device_role(self.device, device_role)
        if article_number:
            result_device &= change_device_article_number(self.device, article_number)
        if model_number:
            result_device &= change_device_model_number(self.device, model_number)
        if serial_number:
            result_device &= change_device_serial_number(self.device, serial_number)
        if device_status:
            result_device &= change_device_status(self.device, device_status)
        if device_exposure:
            result_device &= change_device_exposure(self.device, device_exposure)
        if device_site:
            result_device &= change_device_site(self.device, device_site)
        if device_rack:
            site = device_site if device_site else "Unspecified"
            result_device &= change_device_rack(self.device, device_rack, site)
        if device_location:
            site = device_site if device_site else "Unspecified"
            result_device &= change_device_location(self.device, device_location, site)
        if device_safety:
            result_device &= change_device_safety(self.device, device_safety)
        if device_hver:
            result_device &= change_device_hver(self.device, device_hver)
        if device_hcpe:
            result_device &= change_device_hcpe(self.device, device_hcpe)

        for service in groupsData.get('service'):
            result_service &= add_service(self.device, service.get('ip_address'), service.get('ip_netmask'),
                                          service.get('network_protocol'), service.get('transport_protocol'),
                                          service.get('application_protocol'), service.get('port'))

        for software in groupsData.get('software'):
            result_software &= add_software(self.device, software.get('software_name'), software.get('is_firmware'), software.get('version'))

        if result_device and result_role and result_service and result_software:
            msg = f'Updated Device'
            for findingId in findingIds:
                findings = models.DeviceFinding.objects.filter(id=findingId)
                if findings.exists():
                    finding = findings[0]
                    finding.finding_status = "DONE"
                    finding.save()
        else:
            msg = f'Some error occurred while updating Device'
        logger.info(f"{msg} {self.device} (PK: {self.device.pk})")

        fullPath = request.get_full_path()
        return redirect(fullPath)


class DeviceFindingCreateView(generic.ObjectEditView):
    """ This view handles the creation of a DeviceFinding. """
    queryset = models.DeviceFinding.objects.all()
    form = forms.DeviceFindingForm


# Finding bulk delete view
class DeviceFindingBulkDeleteView(generic.BulkDeleteView):
    """ This view handles the bulk deletion of DeviceFindings. """
    queryset = models.DeviceFinding.objects.all()
    filterset = filtersets.DeviceFindingFilterSet
    table = tables.DeviceFindingTable


class DeviceFindingApply(generic.ObjectEditView):
    """ This view handles the application of a single DeviceFinding to a Device. """
    queryset = Device.objects.all()
    form = forms.DeviceFindingApplyForm
    template_name = 'd3c/devicefinding_apply.html'
    initial_data = None
    device = None
    finding = None
    interface = None

    def _get_choices(self):
        self.device = get_object_or_404(Device, pk=self.initial_data["device"])
        self.finding = models.DeviceFinding.objects.get(pk=self.initial_data["finding"])
        self.interface = find_interface(self.device, self.finding.mac_address, self.finding.ip_address)
        rsp = self.initial_data.get('rsp', 'True') == 'True'
        result = {}

        result['manu_c'] = get_sug(rsp, S_NORMALIZER, S_CHECKER["manufacturer"], "Manufacturer",
                                   str(self.device.device_type.manufacturer), self.finding.manufacturer)
        result['type_c'] = get_sug(rsp, S_NORMALIZER, S_CHECKER["device_type"], "Device Type",
                                   str(self.device.device_type), self.finding.device_type)
        result['role_c'] = get_sug(rsp, S_NORMALIZER, None, "Device Role",
                                   str(self.device.role), self.finding.device_role)
        result['name_c'] = [(0, str(self.device.name)), (1, str(self.finding.device_name))]

        result['family_c'] = get_sug(rsp, S_NORMALIZER, S_CHECKER["device_family"], "Device Family",
                                     str(self.device.device_type.custom_field_data.get('device_family', None)),
                                     self.finding.device_family)

        curr_description = self.device.device_type.description if self.device.device_type.description else None
        result['description_c'] = [(0, str(curr_description)), (1, str(self.finding.description))]

        result['article_c'] = get_sug(rsp, S_NORMALIZER, S_CHECKER["article_number"], "Article Number",
                                      self.device.device_type.custom_field_data.get('article_number', None),
                                      self.finding.article_number)

        curr_model = self.device.device_type.part_number if self.device.device_type.part_number else None
        result['model_c'] = get_sug(rsp, S_NORMALIZER, S_CHECKER["article_number"], "Part Number", str(curr_model),
                                    self.finding.part_number)

        curr_serial = self.device.serial if self.device.serial else None
        result['serial_c'] = [(0, str(curr_serial)), (1, str(self.finding.serial_number))]
        result['status_c'] = get_sug(rsp, None, None, "Device Status", self.device.status, str(self.finding.status))
        result['exposure_c'] = get_sug(rsp, None, None, "Device Exposure",
                                       str(self.device.custom_field_data.get('exposure', None)),
                                       str(self.finding.exposure))
        result['site_c'] = get_sug(False, None, None, "Device Site", str(self.device.site), str(self.finding.site))
        result['rack_c'] = get_sug(False, None, None, "Device Rack", str(self.device.rack), str(self.finding.rack))
        result['location_c'] = get_sug(False, None, None, "Device Location", str(self.device.location), str(self.finding.rack))

        result['safety_c'] = get_sug(False, None, None, "Device Location",
                                     self.device.custom_field_data.get('safety', None),
                                     str(self.finding.is_safety_critical == "True"))

        result['hver_c'] = [(0, self.device.device_type.custom_field_data.get('hardware_version', None)),
                            (1, str(self.finding.hardware_version))]

        if self.finding.is_router and self.interface:
            result['router_c'] = get_sug(rsp, None, None, "Router",
                                         self.interface.custom_field_data.get('is_router', None),
                                         self.finding.is_router)

        return result

    def get(self, request, **kwargs):
        self.initial_data = normalize_querydict(request.GET)
        model = self.queryset.model

        choices = self._get_choices()
        form = self.form(**choices)
        empty = all(len(arg) == 1 or arg[1] is None for arg in choices)

        restrict_form_fields(form, request.user)
        rsp = self.initial_data.get('rsp', 'True') == 'True'
        return_url = self.initial_data.get('return_url', self.get_return_url(request, self.device))

        return render(request, self.template_name, {
            'model': model,
            'device': self.device,
            'finding': self.finding,
            'interface': self.interface,
            'form': form,
            'rsp': not rsp,
            'empty': empty,
            'return_url': return_url,
            'prerequisite_model': get_prerequisite_model(self.queryset),
            **self.get_extra_context(request, self.device),
        })

    def post(self, request, *args, **kwargs):
        logger = logging.getLogger('netbox.views.ObjectEditView')
        self.initial_data = normalize_querydict(request.GET)
        model = self.queryset.model
        post_data = normalize_querydict(request.POST)

        choices = self._get_choices()
        form = self.form(request.POST, **choices)
        empty = all(len(arg) == 1 or arg[1] is None for arg in choices)
        rsp = self.initial_data.get('rsp', 'True') == 'True'
        restrict_form_fields(form, request.user)

        if form.is_valid():
            try:
                with transaction.atomic():
                    # Check that the new object conforms with any assigned object-level permissions
                    if not self.queryset.filter(pk=self.device.pk).exists() or \
                            not models.DeviceFinding.objects.filter(pk=self.finding.pk).exists():
                        raise PermissionsViolation()

                    result_device = True
                    result_role = True
                    result_service = True
                    result_software = True

                    device_type_option = form.cleaned_data['device_type']
                    manu_option = form.cleaned_data['manufacturer']
                    if form.cleaned_data['device_type'] or form.cleaned_data['manufacturer']:
                        device_type_option = form.cleaned_data['device_type'] or '0'
                        manu_option = form.cleaned_data['manufacturer'] or '0'

                        if device_type_option == '0' and manu_option != '0':
                            new_manu = choices['manu_c'][int(manu_option)][1]
                            result_device = change_manufacturer_of_device_type(self.device, new_manu)
                        elif device_type_option != '0' and manu_option == '0':
                            new_dt = choices['type_c'][int(device_type_option)][1]
                            result_device = change_device_type_keep_manufacturer(self.device, new_dt)
                        elif device_type_option != '0' and manu_option != '0':
                            new_manu = choices['manu_c'][int(manu_option)][1]
                            new_dt = choices['type_c'][int(device_type_option)][1]
                            result_device = change_device_type_and_manufacturer(self.device, new_dt, new_manu)

                    device_desc_option = form.cleaned_data['device_description'] or '0'
                    if device_desc_option != '0':
                        new_dc = choices['description_c'][int(device_desc_option)][1]
                        result_device &= change_device_description(self.device, new_dc)

                    device_name_option = form.cleaned_data['device_name'] or '0'
                    if device_name_option != '0':
                        new_dn = choices['name_c'][int(device_name_option)][1]
                        result_device &= change_device_name(self.device, new_dn)

                    device_family_option = form.cleaned_data['device_family'] or '0'
                    if device_family_option != '0':
                        new_device_family = choices['family_c'][int(device_family_option)][1]
                        result_device &= change_device_family(self.device, new_device_family)

                    device_role_option = form.cleaned_data['device_role'] or '0'
                    if device_role_option != '0':
                        new_device_role = choices['role_c'][int(device_role_option)][1]
                        result_role = change_device_role(self.device, new_device_role)

                    device_article_option = form.cleaned_data['device_article'] or '0'
                    if device_article_option != '0':
                        new_device_article = choices['article_c'][int(device_article_option)][1]
                        result_device &= change_device_article_number(self.device, new_device_article)

                    device_model_option = form.cleaned_data['device_model'] or '0'
                    if device_model_option != '0':
                        new_device_model = choices['model_c'][int(device_model_option)][1]
                        result_device &= change_device_model_number(self.device, new_device_model)

                    device_serial_option = form.cleaned_data['device_serial'] or '0'
                    if device_serial_option != '0':
                        new_device_serial = choices['serial_c'][int(device_serial_option)][1]
                        result_device &= change_device_serial_number(self.device, new_device_serial)

                    device_status_option = form.cleaned_data['device_status'] or '0'
                    if device_status_option != '0':
                        new_device_status = choices['status_c'][int(device_status_option)][1]
                        result_device &= change_device_status(self.device, new_device_status)

                    device_exposure_option = form.cleaned_data['device_exposure'] or '0'
                    if device_exposure_option != '0':
                        new_device_exposure = choices['exposure_c'][int(device_exposure_option)][1]
                        result_device &= change_device_exposure(self.device, new_device_exposure)

                    device_site_option = form.cleaned_data['device_site'] or '0'
                    if device_site_option != '0':
                        new_device_site = choices['site_c'][int(device_site_option)][1]
                        result_device &= change_device_site(self.device, new_device_site)

                    device_rack_option = form.cleaned_data['device_rack'] or '0'
                    if device_rack_option != '0':
                        new_device_rack = choices['rack_c'][int(device_rack_option)][1]
                        site = choices['site_c'][int(device_site_option)][1] if device_site_option != '0' else "Unspecified"
                        result_device &= change_device_rack(self.device, new_device_rack, site)

                    device_location_option = form.cleaned_data['device_location'] or '0'
                    if device_location_option != '0':
                        new_device_location = choices['location_c'][int(device_location_option)][1]
                        site = choices['site_c'][int(device_site_option)][1] if device_site_option != '0' else "Unspecified"
                        result_device &= change_device_location(self.device, new_device_location, site)

                    device_safety_option = form.cleaned_data['device_safety'] or '0'
                    if device_safety_option != '0':
                        new_device_safety = choices['safety_c'][int(device_safety_option)][1]
                        result_device &= change_device_safety(self.device, new_device_safety)

                    device_router_option = form.cleaned_data['device_router'] or '0'
                    if device_router_option != '0':
                        new_device_router = choices['router_c'][int(device_router_option)][1]
                        result_device &= change_device_router(self.device, self.finding.mac_address,
                                                              self.finding.ip_address, new_device_router)

                    device_hver_option = form.cleaned_data['device_hver'] or '0'
                    if device_hver_option != '0':
                        new_device_hver = choices['hver_c'][int(device_hver_option)][1]
                        result_device &= change_device_hver(self.device, new_device_hver)

                    device_hcpe_option = form.cleaned_data['device_hcpe'] or '0'
                    if device_hcpe_option != '0':
                        new_device_hcpe = choices['hcpe_c'][int(device_hcpe_option)][1]
                        result_device &= change_device_hcpe(self.device, new_device_hcpe)

                    service_option = form.cleaned_data.get('add_service', False)
                    if service_option:
                        result_service = add_service(self.device, self.finding.ip_address, self.finding.ip_netmask,
                                                     self.finding.network_protocol, self.finding.transport_protocol,
                                                     self.finding.application_protocol, self.finding.port)

                    software_option = form.cleaned_data.get('add_software', False)
                    if software_option:
                        result_software = add_software(self.device, self.finding.software_name,
                                                       self.finding.is_firmware, self.finding.version)

                    if result_device and result_role and result_service and result_software:
                        try:
                            self.finding.finding_status = "DONE"
                            self.finding.save()
                        except Exception as e:
                            msg = f'Error occurred changing status of DeviceFinding'
                        else:
                            msg = f'Updated {self.queryset.model._meta.verbose_name}'
                    else:
                        msg = f'Some error occurred while updating {self.queryset.model._meta.verbose_name}'

                    logger.info(f"{msg} {self.device} (PK: {self.device.pk})")
                    if hasattr(self.device, 'get_absolute_url'):
                        msg = mark_safe(f'{msg} <a href="{self.device.get_absolute_url()}">{escape(self.device)}</a>')
                    else:
                        msg = f'{msg} {self.device}'
                    messages.success(request, msg)

                    return redirect(self.device.get_absolute_url())
            except (AbortRequest, PermissionsViolation) as e:
                logger.debug(e.message)
                form.add_error(None, e.message)
                clear_events.send(sender=self)
        else:
            logger.debug("Form validation failed")

        return render(request, self.template_name, {
            'model': model,
            'device': self.device,
            'finding': self.finding,
            'interface': self.interface,
            'form': form,
            'rsp': not rsp,
            'empty': empty,
            'return_url': self.initial_data.get('return_url', self.get_return_url(request, self.device)),
            'prerequisite_model': get_prerequisite_model(self.queryset),
            **self.get_extra_context(request, self.device),
        })


class DeviceFindingCreateDeviceView(generic.ObjectEditView):
    """ Handles the creation of a new Device based on a DeviceFinding. """
    queryset = Device.objects.all()
    form = forms.DeviceFindingCreateDeviceForm
    default_return_url = "plugins:d3c:devicefinding_list"
    template_name = 'd3c/create_device.html'

    def get(self, request, *args, **kwargs):
        obj = self.get_object(**kwargs)
        obj = self.alter_object(obj, request, args, kwargs)
        model = self.queryset.model

        initial_data = normalize_querydict(request.GET)
        df_pk = initial_data["df"]
        df = models.DeviceFinding.objects.get(pk=df_pk)

        ip = get_ip(df.ip_address, df.ip_netmask)
        mac = get_mac(df.mac_address)

        if not ip and not mac:
            if "," in (df.ip_address or df.mac_address):
                msg = (f"Lists of IP and MAC Address unsupported. "
                       f"Use Split or Edit Button for DeviceFinding {df_pk}.")
            else:
                msg = (f"Can not parse IP or MAC Address for id {df_pk}."
                       f"Check if IP and/or MAC Address has a valid format.")
            messages.error(request, msg)
            return redirect(self.default_return_url)

        form = self.form()
        restrict_form_fields(form, request.user)

        return render(request, self.template_name, {
            'model': model,
            'object': obj,
            'form': form,
            'ip': df.ip_address,
            'mac': df.mac_address,
            'return_url': self.get_return_url(request, obj),
            'prerequisite_model': get_prerequisite_model(self.queryset),
            **self.get_extra_context(request, obj),
        })

    def post(self, request, *args, **kwargs):
        logger = logging.getLogger('netbox.views.ObjectEditView')

        device = self.get_object(**kwargs)
        form = self.form(data=request.POST)
        restrict_form_fields(form, request.user)

        initial_data = normalize_querydict(request.GET)
        df = models.DeviceFinding.objects.get(pk=initial_data["df"])

        ip = get_ip(df.ip_address, df.ip_netmask)
        mac = get_mac(df.mac_address)

        if form.is_valid() and (ip or mac):
            logger.debug("Form validation was successful")

            try:
                with transaction.atomic():
                    device.site, _ = Site.objects.get_or_create(name='PoC')
                    device.manufacturer, _ = Manufacturer.objects.get_or_create(name='Unspecified')
                    device.role, _ = DeviceRole.objects.get_or_create(name='Unspecified')
                    device.device_type, _ = DeviceType.objects.get_or_create(manufacturer=device.manufacturer,
                                                                             model='Unspecified')
                    device.name = form.cleaned_data['device_name']
                    device.comments = form.cleaned_data['comments']
                    device.save()

                    create_and_assign_interface(device, form.cleaned_data['interface_name'], ip, mac)

                    # Check that the new object conforms with any assigned object-level permissions
                    if not self.queryset.filter(pk=device.pk).exists():
                        raise PermissionsViolation()

                msg = f'Created {self.queryset.model._meta.verbose_name}'

                logger.info(f"{msg} {device} (PK: {device.pk})")
                if hasattr(device, 'get_absolute_url'):
                    msg = mark_safe(f'{msg} <a href="{device.get_absolute_url()}">{escape(device)}</a>')
                else:
                    msg = f'{msg} {device}'
                messages.success(request, msg)

                return redirect(self.default_return_url)

            except (AbortRequest, PermissionsViolation) as e:
                logger.debug(e.message)
                form.add_error(None, e.message)
                clear_events.send(sender=self)
        else:
            logger.debug("Form validation failed")

        return render(request, self.template_name, {
            'object': device,
            'form': form,
            'return_url': self.get_return_url(request, device),
            **self.get_extra_context(request, device),
        })


# Finding create view
class DeviceFindingEditView(generic.ObjectEditView):
    """ Handles the request of editing a DeviceFinding. """
    queryset = models.DeviceFinding.objects.all()
    form = forms.DeviceFindingEditForm
    template_name = 'd3c/devicefinding_edit.html'
    default_return_url = "plugins:d3c:devicefinding_list"

    def post(self, request, **kwargs):
        logger = logging.getLogger('netbox.views.ObjectEditView')

        device_finding = self.get_object(**kwargs)
        form = self.form(data=request.POST)

        ip = get_ip(device_finding.ip_address, device_finding.ip_netmask)
        mac = get_mac(device_finding.mac_address)
        if form.is_valid():
            logger.debug("Form validation was successful")

            device_finding.ip_address = form.cleaned_data["ip_address"]
            device_finding.ip_netmask = form.cleaned_data["ip_netmask"]
            device_finding.mac_address = form.cleaned_data["mac_address"]
            device_finding.save()

            device = form.cleaned_data['device']
            interface_name = form.cleaned_data['interface_name']

            # Only updating DeviceFinding
            if not device and not interface_name:
                messages.success(request, f"Updated Addresses.")
                return redirect(self.default_return_url)

            ip = get_ip(device_finding.ip_address, device_finding.ip_netmask)
            mac = get_mac(device_finding.mac_address)

            if device or interface_name:
                mes = None
                if "," in (device_finding.ip_address or device_finding.mac_address):
                    mes = ("Lists of addresses are not supported for editing an Interface.")
                elif not interface_name:
                    mes = ("Provide an Interface Name.")
                elif not device:
                    mes = ("Provide a Devicee.")

                if mes:
                    form.add_error(None, mes)
                    return render(request, self.template_name, {
                        'object': device_finding,
                        'form': form,
                        'return_url': self.get_return_url(request, device_finding),
                        **self.get_extra_context(request, device_finding),
                    })

            if device and interface_name:
                interface = None
                try:
                    interface = Interface.objects.get(name=interface_name, device=device, type="other")
                except ObjectDoesNotExist:
                    pass

                if interface == None:
                   try:
                        with transaction.atomic():
                            create_and_assign_interface(device, interface_name, ip, mac)

                        msg = f'Created interface {interface_name} for {device.name} '

                        if hasattr(device, 'get_absolute_url'):
                            msg = mark_safe(f'{msg} <a href="{device_finding.get_absolute_url()}">{escape(device_finding)}</a>')
                        else:
                            msg = f'{msg} {device}'
                        messages.success(request, msg)

                        return redirect(self.default_return_url)

                   except (AbortRequest, PermissionsViolation) as e:
                       logger.debug(e.message)
                       form.add_error(None, e.message)
                       clear_events.send(sender=self)
                else:
                    if mac and interface.mac_address is None:
                        try:
                                interface.mac_address = mac
                                interface.save()
                                msg = f'Interface {interface_name} in use and MAC was updated'
                                messages.success(request, msg)
                        except Exception as e:
                            pass
                    elif ip and ip not in [str(interface_ip.address) for interface_ip in interface.ip_addresses.all()]:
                        try:
                            ipaddr = IPAddress(address=ip, assigned_object=interface)
                            ipaddr.save()
                            msg = f'Interface {interface_name} in use and IP was added'
                            messages.success(request, msg)
                        except Exception as e:
                            pass
                    else:
                        msg = f'Interface {interface_name} in use'
                        messages.error(request, msg)

                    return redirect(self.default_return_url)

        else:
            logger.debug("Form validation failed")

        return render(request, self.template_name, {
            'object': device_finding,
            'form': form,
            'return_url': self.get_return_url(request, device_finding),
            **self.get_extra_context(request, device_finding),
        })


class DeviceFindingDeleteView(generic.ObjectDeleteView):
    """ Handles the request for deleting a DeviceFinding. """
    queryset = models.DeviceFinding.objects.all()


class FindingStdImportView(generic.BulkImportView):
    """  Handles the request for the standard import of DeviceFindings. """
    queryset = models.DeviceFinding.objects.all()
    model_form = forms.DeviceFindingImportForm
    default_return_url = "plugins:d3c:devicefinding_list"


# Finding import view
class FindingImportView(FormView):
    """ View for bulk-importing Findings from a CSV file. """
    queryset = models.DeviceFinding.objects.all()
    template_name = 'd3c/findings_import.html'
    success_url = "plugins:d3c:devicefinding_list"
    stringMiner = StringMiner()

    def get(self, request, *args, **kwargs):
        form = forms.FindingImportForm(initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        examples = {}
        fullTable = None
        form = forms.FindingImportForm(request.POST, request.FILES)
        if form.is_valid():
            cleaned_data = form.cleaned_data
            if cleaned_data.get('submit_button') == 'data_submit':
                print("Creating Findings...")

                try:
                    if not cleaned_data.get('source', None):
                        raise ValidationError('Source must have a value')

                    # Iterate through data and bind each record to a new model form instance.
                    with transaction.atomic():
                        new_objs, countDup, countFail = self.create_objects(form, request)
                        # Enforce object-level permissions
                        if self.queryset.filter(pk__in=[obj.pk for obj in new_objs]).count() != len(new_objs):
                            raise PermissionsViolation

                    if new_objs or countDup or countFail:
                        msg = f"Imported {len(new_objs)} new, ignored {countDup} duplicate DeviceFindings, failed {countFail}"
                        messages.success(request, msg)
                        return redirect(self.success_url)

                except (AbortTransaction, ValidationError) as e:
                    form.add_error(None, e.message)
                    clear_events.send(sender=self)
                except (AbortRequest, PermissionsViolation) as e:
                    form.add_error(None, e.message)
                    clear_events.send(sender=self)
                except IntegrityError:
                    pass
                return render(request, self.template_name, {'form': form, 'examples': examples})

            if cleaned_data.get('submit_button') == 'string_matcher':
                print("Running String Matcher")
                time_start('stringMatch')
                catMap = {}
                for category in self.stringMiner.re_attributes:
                    csvName = 'mined_' + category
                    catMap[category] = csvName
                    form.csv_headers[csvName] = len(form.csv_headers)

                for record in form.csv_records:
                    recordString = ''
                    for value in record.values():
                        recordString += value + ' '
                    # Note: Additional logic w.r.t. the StrinMiner can be added here.
                    result = self.stringMiner.match(recordString, ignore_case=True)
                    if result:
                        print('    Search: ' + recordString)
                        print('    Result: ' + str(result))
                        for name, subValue in result.items():
                            record[catMap[name]] = result[name]
                form.writeData(form.csv_headers, form.csv_records)
                time_end()

            if cleaned_data.get('submit_button') == 'mapping_save':
                print("Saving Mapping...")
                mapping_data = {}
                mapping_name = cleaned_data['mapping_name']
                if mapping_name:
                    mapping_type = cleaned_data['format']
                    for name, fieldName in form.templates.items():
                        mapping_data[fieldName] = cleaned_data[fieldName]
                    mappings = models.Mapping.objects.filter(name=mapping_name, type=mapping_type)
                    if mappings:
                        mapping = mappings.get()
                        mapping.data = mapping_data
                        print("  Updating...")
                    else:
                        mapping = models.Mapping(
                            name=mapping_name,
                            type=mapping_type,
                            data=mapping_data
                        )
                    mapping.save()

            if cleaned_data.get('submit_button') == 'mapping_load':
                print("Loading Mapping...")
                mapping = cleaned_data['mapping']
                if mapping:
                    cleaned_data['mapping_name'] = mapping.name
                    for name, fieldName in form.templates.items():
                        if fieldName in mapping.data:
                            cleaned_data[fieldName] = mapping.data[fieldName]

            if cleaned_data.get('submit_button') == 'mapping_delete':
                print("Deleting Mapping...")
                mapping = cleaned_data['mapping']
                if mapping:
                    mapping.delete()

            generateTable = cleaned_data.get('submit_button') == 'generate_table'

            if form.step == 1:
                if generateTable:
                    fullTableHeaders = ["Error"]
                    fullTableData = []
                    fullTable = {
                        'headers': fullTableHeaders,
                        'data': fullTableData
                    }
                    for idx in range(len(form.csv_records)):
                        fullTableData.append([""])
                for name, fieldName in form.templates.items():
                    if name in form.csv_headers and not form.cleaned_data[fieldName]:
                        form.cleaned_data[fieldName] = '{' + name + '}'
                        print("Template: {} -> {}".format(fieldName, form.cleaned_data[fieldName]))
                    if len(form.csv_records) > 0 and form.cleaned_data[fieldName]:
                        template = form.cleaned_data[fieldName]
                        try:
                            examples[fieldName] = fillTemplate(template, form.csv_records[0])
                        except Exception as e:
                            examples[fieldName] = str(e)
                        if generateTable:
                            fullTableHeaders.append(pretty_name(fieldName))
                            idx = 0
                            for record in form.csv_records:
                                try:
                                    fullTableData[idx].append(fillTemplate(template, record))
                                except Exception as e:
                                    fullTableData[idx].append("[Error]")
                                    fullTableData[idx][0] += str(e)
                                idx += 1

        if not form.cleaned_data.get('source', None) and form.cleaned_data.get('file_name', None):
            form.cleaned_data['source'] = form.cleaned_data.get('file_name')
        form = forms.FindingImportForm(form.cleaned_data, request.FILES)

        return render(request, self.template_name, {'form': form, 'examples': examples, 'fullTable': fullTable})

    def create_objects(self, form, request):
        new_objects = []
        countDup = 0
        countFail = 0
        for record in form.csv_records:
            data = {}
            try:
                for name, fieldName in form.templates.items():
                    value = fillTemplate(form.cleaned_data[fieldName], record)
                    if value:
                        data[name] = value
            except Exception as e:
                countFail += 1
                continue

            existing = models.DeviceFinding.objects.filter(**data)
            if existing:
                countDup += 1
                continue
            data['finding_status'] = 'NEW'
            findingForm = forms.DeviceFindingForm(data)

            # Validate each new object independently.
            if findingForm.is_valid():
                obj = findingForm.save()
                new_objects.append(obj)
            else:
                for errorField, error in findingForm.errors.items():
                    form.add_error(errorField, error)
                raise IntegrityError()

        return new_objects, countDup, countFail


class FindingImportForDeviceView(View):
    """ View for bulk-importing Findings from a CSV file. """
    template_name = "d3c/findings_import.html"
    form_class = forms.FindingImportForm
    queryset = models.DeviceFinding.objects.all()
    default_return_url = "plugins:d3c:finding_list"

    def get(self, request, *args, **kwargs):
        form = self.form_class()
        return render(request, self.template_name, {'form': form, 'model': models.DeviceFinding})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            # <process form cleaned data>
            return HttpResponseRedirect(self.default_return_url)

        return render(request, self.template_name, {'form': form, 'model': models.DeviceFinding})


class SoftwareView(generic.ObjectView):
    """ Handles the request of displaying a single Software objects. """
    queryset = models.Software.objects.all()
    table = tables.SoftwareTable

    def get_extra_context(self, request, instance):
        #related_models =  models.ProductRelationship.objects.restrict(request.user, 'view').filter(target_software=instance.pk)

        return {
            'related_models': None,
        }


class SoftwareListView(generic.ObjectListView):
    """ Handles the request of displaying a multiple Software objects as table. """
    def get_queryset(self, request):
        queryset = models.Software.objects.all()
        return queryset

    table = tables.SoftwareTable
    #template_name = 'd3c/object_list_custom.html'


# Software view for one device
@register_model_view(Device, name='softwarelistfordeviceview', path='software')
class SoftwareListForDeviceView(View):
    """ Handles the request of displaying multiple Software objects associated to a Device. """
    base_template = 'dcim/device.html'
    template_name = 'd3c/software_for_device.html'
    table = tables.SoftwareTable

    tab = ViewTab(
        label='ProductRelationships',
        badge=lambda obj: models.ProductRelationship.objects.filter(Q(source_type_id=ContentType.objects.get_for_model(Device), source_id=obj.pk) |
                                                                    Q(destination_type_id=ContentType.objects.get_for_model(Device), destination_id=obj.pk)).count(),
        permission='findings.view_stuff'
    )

    def get(self, request, **kwargs):
        obj = get_object_or_404(Device, **kwargs)
        device_ct = ContentType.objects.get_for_model(Device)
        #pr_source = models.ProductRelationship.objects.filter(source_type_id=device_ct.id, source_id=self.kwargs["pk"])
        pr = models.ProductRelationship.objects.filter(Q(source_type_id=device_ct.id, source_id=self.kwargs["pk"]) |
                                                       Q(destination_type_id=device_ct.id, destination_id=self.kwargs["pk"]))
        pr_table = tables.ProductRelationshipTable(pr)
        return render(request, self.template_name, {
            'object': obj,
            'table': pr_table,
            'base_template': self.base_template,
            'tab': self.tab,
        })


@register_model_view(models.Software, name='deviceslistforsoftwareview', path='devices')
class DeviceListForSoftwareView(View):
    """ Handles the request for displaying the devices associated to a Software object. """
    base_template = 'd3c/software.html'
    template_name = 'd3c/devices_for_software.html'
    table = DeviceTable

    def get(self, request, **kwargs):
        obj = get_object_or_404(models.Software, **kwargs)
        devices = Device.objects.filter(software=self.kwargs["pk"])
        devices_table = DeviceTable(devices)
        return render(request, self.template_name, {
            'object': obj,
            'table': devices_table,
            'base_template': self.base_template,
            'tab': self.tab,
        })


class SoftwareEditView(generic.ObjectEditView):
    """ Handles the request for editing Software. """
    queryset = models.Software.objects.all()
    form = forms.SoftwareForm


class SoftwareDeleteView(generic.ObjectDeleteView):
    """ Handles the request for deleting Software. """
    queryset = models.Software.objects.all()


class CommunicationView(generic.ObjectView):
    """ Handles the request for displaying a single Communication. """
    queryset = models.Communication.objects.all()
    table = tables.CommunicationTable


class CommunicationListView(generic.ObjectListView):
    """ Handles the request for displaying a multiple Communications as table. """
    def get_queryset(self, request):
        queryset = models.Communication.objects.all()
        return queryset

    table = tables.CommunicationTable
    filterset = filtersets.CommunicationFilterSet
    filterset_form = forms.CommunicationFilterForm


class CommunicationFindingEditView(generic.ObjectEditView):
    """ Handles the request for editing CommunicationFinding. """
    queryset = models.CommunicationFinding.objects.all()
    form = forms.CommunicationFindingEditForm


class CommunicationFindingMap(GetReturnURLMixin, BaseMultiObjectView):
    """ Handles the request for mapping CommunicationFindings. """
    queryset = models.CommunicationFinding.objects.all()

    def get_required_permission(self):
        return '{}.{}_{}'.format('d3c', 'edit', 'CommunicationFinding')

    def post(self, request):
        selected_objects = self.queryset.filter(
            pk__in=request.POST.getlist('pk'),
        )
        with transaction.atomic():
            count = 0
            for communication_finding in selected_objects:
                if communication_finding.has_2_predicted_devices and communication_finding.finding_status == "NEW":
                    src, dst = communication_finding.get_matched_device()
                    if src and dst:
                        a_comm, created = models.Communication.objects.get_or_create(
                            source_device=Device.objects.get(id=src.id),
                            destination_device=Device.objects.get(id=dst.id),
                            source_ip_addr=IPAddress.objects.get(address=communication_finding.source_ip + '/24'),
                            destination_ip_addr=IPAddress.objects.get(address=communication_finding.destination_ip + '/24'),
                            destination_port=communication_finding.destination_port,
                            network_protocol=communication_finding.network_protocol,
                            transport_protocol=communication_finding.transport_protocol,
                            application_protocol=communication_finding.application_protocol)
                        a_comm.save()
                        count += 1
                    communication_finding.finding_status = "DONE"
                    communication_finding.save()
                else:
                    messages.error(request, f"Mapping of record with ID {communication_finding.pk} not possible.")

            model_name = self.queryset.model._meta.verbose_name_plural
            if count > 0:
                messages.success(request, f"Mapped {count} {model_name}")

        return redirect(self.get_return_url(request))

class CommunicationFindingReject(GetReturnURLMixin, BaseMultiObjectView):
    """ Handles the request for rejecting CommunicationFindings. """
    queryset = models.CommunicationFinding.objects.all()

    def get_required_permission(self):
        return '{}.{}_{}'.format('d3c', 'edit', 'CommunicationFinding')

    def post(self, request):
        selected_objects = self.queryset.filter(
            pk__in=request.POST.getlist('pk'),
        )

        with transaction.atomic():
            count = 0
            for communication_finding in selected_objects:
                print (communication_finding)
                communication_finding.finding_status = "REJECT"
                communication_finding.save()
                count += 1

            model_name = self.queryset.model._meta.verbose_name_plural
            if count > 0:
                messages.success(request, f"{count} {model_name} rejected")

        return redirect(self.get_return_url(request))

# Communication view for one device
@register_model_view(Device, name='clientcommunicationlistfordeviceview', path='clientcommunication')
class ClientCommunicationListForDeviceView(View):
    """ Handles the request for displaying Client-Communications for a Device."""
    base_template = 'dcim/device.html'
    template_name = 'd3c/communication_for_device.html'
    table = tables.CommunicationTable

    tab = ViewTab(
        label='Client Communication',
        badge=lambda obj: models.Communication.objects.filter(source_device=obj).count(),
        permission='findings.view_stuff'
    )

    def get(self, request, **kwargs):
        obj = get_object_or_404(Device, **kwargs)
        communication = models.Communication.objects.filter(source_device=self.kwargs["pk"])
        communication_table = tables.CommunicationTable(communication)
        return render(request, self.template_name, {
            'object': obj,
            'table': communication_table,
            'base_template': self.base_template,
            'tab': self.tab,
        })


@register_model_view(Device, name='servercommunicationlistfordeviceview', path='servercommunication')
class ServerCommunicationListForDeviceView(View):
    """ Handles the request for displaying Server-Communications for a Device."""
    base_template = 'dcim/device.html'
    template_name = 'd3c/communication_for_device.html'
    table = tables.CommunicationTable

    tab = ViewTab(
        label='Server Communication',
        badge=lambda obj: models.Communication.objects.filter(destination_device=obj).count(),
        permission='findings.view_stuff'
    )

    def get(self, request, **kwargs):
        obj = get_object_or_404(Device, **kwargs)
        communication = models.Communication.objects.filter(destination_device=self.kwargs["pk"])
        communication_table = tables.CommunicationTable(communication)
        return render(request, self.template_name, {
            'object': obj,
            'table': communication_table,
            'base_template': self.base_template,
            'tab': self.tab,
        })


@register_model_view(models.Communication, name='deviceslistforcommunicationview', path='devices')
class DeviceListForCommunicationView(View):
    """ Handles the request for displaying devices for one communication."""
    base_template = 'd3c/communication.html'
    template_name = 'd3c/devices_for_communication.html'
    table = DeviceTable

    tab = ViewTab(
        label='Devices',
        badge=lambda obj: Device.objects.filter(sourceForCommunications=obj).count(),
        permission='findings.view_stuff'
    )

    def get(self, request, **kwargs):
        obj = get_object_or_404(models.Communication, **kwargs)
        devices = Device.objects.filter(SourceForCommunication=self.kwargs["pk"])
        devices_table = DeviceTable(devices)
        return render(request, self.template_name, {
            'object': obj,
            'table': devices_table,
            'base_template': self.base_template,
            'tab': self.tab,
        })


ipv4_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

# Communication edit view
class CommunicationEditView(generic.ObjectEditView):
    """ Handles the request for editing Communications. """
    queryset = models.Communication.objects.all()
    form = forms.CommunicationForm

    def post(self, request, *args, **kwargs):
        device = self.get_object(**kwargs)
        source_ip = request.POST['source_ip_addr']
        destination_ip = request.POST['destination_ip_addr']
        destination_port = request.POST['destination_port']
        if not destination_port:
            destination_port = None
        network_protocol = request.POST['network_protocol']
        if not network_protocol:
            network_protocol=None
        transport_protocol = request.POST['transport_protocol']
        if not transport_protocol:
            transport_protocol = None
        application_protocol = request.POST['application_protocol']
        if not application_protocol:
            application_protocol = None
        src, dst = self.get_matched_device(source_ip, destination_ip)

        with transaction.atomic():
            if device.id:
                a_comm = models.Communication.objects.get(id=device.id)
                a_comm.source_device = Device.objects.get(id=src.id)
                a_comm.destination_device = Device.objects.get(id=dst.id)
                a_comm.source_ip_addr = IPAddress.objects.get(id=source_ip)
                a_comm.destination_ip_addr = IPAddress.objects.get(id=destination_ip)
                a_comm.destination_port = destination_port
                a_comm.network_protocol = network_protocol
                a_comm.transport_protocol = transport_protocol
                a_comm.application_protocol = application_protocol
                a_comm.save()
                messages.success(request, f"Communication record changed")
            else:
                if src and dst:
                    a_comm, created = models.Communication.objects.get_or_create(
                        source_device=Device.objects.get(id=src.id),
                        destination_device=Device.objects.get(id=dst.id),
                        source_ip_addr=IPAddress.objects.get(id=source_ip),
                        destination_ip_addr=IPAddress.objects.get(id=destination_ip),
                        destination_port=destination_port,
                        network_protocol=network_protocol,
                        transport_protocol=transport_protocol,
                        application_protocol=application_protocol)
                    a_comm.save()
                else:
                    messages.error(request, f"Creation of communication record not possible.")
                messages.success(request, f"Communication record created")

        return redirect(self.get_return_url(request))

    def get_device_by_ip(self, ip_id):
        try:
            source_if = IPAddress.objects.get(id=ip_id,
                                           assigned_object_type=ContentType.objects.get_for_model(Interface))
            if source_if:
                return Interface.objects.get(id=source_if.assigned_object_id).device
            return None
        except (ObjectDoesNotExist, MultipleObjectsReturned, ValidationError, NoReverseMatch) as error:
            return None

    def get_matched_device(self, source_ip, destination_ip):
        source_device_by_ip = None
        destination_device_by_ip = None
        if source_ip:
            source_device_by_id = self.get_device_by_ip(source_ip)
        if destination_ip:
            destination_device_by_id = self.get_device_by_ip(destination_ip)
        return (source_device_by_id, destination_device_by_id)


class CommunicationImportView(generic.BulkImportView):
    """ View for bulk-importing Communication from a CSV file. """
    queryset = models.Communication.objects.all()
    model_form = forms.CommunicationImportForm
    default_return_url = "plugins:d3c:communication_list"


class CommunicationDeleteView(generic.ObjectDeleteView):
    """ View for deleting Communications. """
    queryset = models.Communication.objects.all()


class CommunicationFindingView(generic.ObjectView):
    """ View for displaying a single CommunicationFinding. """
    queryset = models.CommunicationFinding.objects.all()
    table = tables.CommunicationFindingTable


class CommunicationFindingListView(generic.ObjectListView):
    """ View for displaying multiple CommunicationFindings as table. """
    # def get_queryset(self, request):
    #     queryset = models.CommunicationFinding.objects.filter(finding_status="NEW")
    #     return queryset

    queryset = models.CommunicationFinding.objects.filter(finding_status="NEW")
    table = tables.UnassignedCommunicationFindingTable
    filterset = filtersets.CommunicationFindingFilterSet
    filterset_form = forms.CommunicationFindingFilterForm
    template_name = 'd3c/communicationfinding_list.html'
    actions = {
        'add': {'add'},
        'import': {'add'},
        'edit': {'change'},
        'export': set(),
        'bulk_sync': {'sync'}}


# Communication import view
class CommunicationFindingImportView(generic.BulkImportView):
    """ View for importing CommunicationFindings. """
    queryset = models.CommunicationFinding.objects.all()
    model_form = forms.CommunicationFindingImportForm
    default_return_url = "plugins:d3c:communicationfinding_list"


class CommunicationFindingDeleteView(generic.ObjectDeleteView):
    """ View for deleting CommunicationFindings. """
    queryset = models.CommunicationFinding.objects.all()


class MappingView(generic.ObjectView):
    """ View for displaying a single Mapping. """
    queryset = models.Mapping.objects.all()
    table = tables.MappingTable


class MappingListView(generic.ObjectListView):
    """ View for displaying a multiple Mappings as table. """
    def get_queryset(self, request):
        queryset = models.Mapping.objects.all()
        return queryset

    table = tables.MappingTable
    filterset = filtersets.MappingFilterSet
    filterset_form = forms.MappingFilterForm


class MappingEditView(generic.ObjectEditView):
    """ View for editing Mappings. """
    queryset = models.Mapping.objects.all()
    form = forms.MappingForm


class MappingDeleteView(generic.ObjectDeleteView):
    """ View for deleting Mappings. """
    queryset = models.Mapping.objects.all()


def get_value_or_none(k, d):
    if k in d.keys():
        return d[k]
    else:
        return None


@csrf_exempt
def DeviceFindingImport(request):
    print("DeviceFindingImport")
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)
    if request.method == 'POST' and user is not None:
        request.user = user
        uploaded_file = request.FILES['files']
        help = json.loads(uploaded_file.read().decode('utf8'))
        for x in help:
            application_protocol = get_value_or_none('application_protocol', x)
            article_number = get_value_or_none('article_number', x)
            confidence = get_value_or_none('confidence', x)
            description = get_value_or_none('description', x)
            device_family = get_value_or_none('device_family', x)
            device_name = get_value_or_none('device_name', x)
            device_role = get_value_or_none('device_role', x)
            device_type = get_value_or_none('device_type', x)
            hw_version = get_value_or_none('hw_version', x)
            ip_address = get_value_or_none('ip_address', x)
            ip_netmask = get_value_or_none('ip_netmask', x)
            is_firmware = get_value_or_none('is_firmware', x)
            is_router = get_value_or_none('is_router', x)
            location = get_value_or_none('location', x)
            mac_address = get_value_or_none('mac_address', x)
            manufacturer = get_value_or_none('manufacturer', x)
            oui = get_value_or_none('oui', x)
            network_protocol = get_value_or_none('network_protocol', x)
            port = get_value_or_none('port', x)
            serial_number = get_value_or_none('serial_number', x)
            source = get_value_or_none('source', x)
            software_name = get_value_or_none('software_name', x)
            sw_version = get_value_or_none('sw_version', x)
            transport_protocol = get_value_or_none('transport_protocol', x)
            found, created = models.DeviceFinding.objects.get_or_create(application_protocol=application_protocol,
                                                                        article_number=article_number,
                                                                        confidence=confidence,
                                                                        description=description,
                                                                        device_family=device_family,
                                                                        device_name=device_name,
                                                                        device_role=device_role,
                                                                        device_type=device_type,
                                                                        hardware_version=hw_version,
                                                                        ip_address=ip_address,
                                                                        ip_netmask=ip_netmask,
                                                                        is_firmware=is_firmware,
                                                                        is_router=is_router,
                                                                        location=location,
                                                                        mac_address=mac_address,
                                                                        manufacturer=manufacturer,
                                                                        oui=oui,
                                                                        network_protocol=network_protocol,
                                                                        port=port,
                                                                        serial_number=serial_number,
                                                                        source=source,
                                                                        software_name=software_name,
                                                                        transport_protocol=transport_protocol,
                                                                        version=sw_version
                                                                        )
    else:
        print("not authenticated")
    return HttpResponse()


@csrf_exempt
def CommunicationFindingImport(request):
    print("CommunicationFindingImport")
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)
    if request.method == 'POST' and user is not None:
        request.user = user
        uploaded_file = request.FILES['files']
        help = json.loads(uploaded_file.read().decode('utf8'))
        for x in help:
            source_ip = get_value_or_none('source_ip', x)
            destination_ip = get_value_or_none('destination_ip', x)
            destination_port = get_value_or_none('destination_port', x)
            source = get_value_or_none('source', x)
            application_protocol = get_value_or_none('application_protocol', x)
            transport_protocol = get_value_or_none('transport_protocol', x)
            network_protocol = get_value_or_none('network_protocol', x)
            found, created = models.CommunicationFinding.objects.get_or_create(source=source,
                                                                               source_ip=source_ip,
                                                                               destination_ip=destination_ip,
                                                                               destination_port=destination_port,
                                                                               network_protocol=network_protocol,
                                                                               transport_protocol=transport_protocol,
                                                                               application_protocol=application_protocol)
    else:
        print("not authenticated")
    return HttpResponse()

######

