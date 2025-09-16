from netbox.plugins import PluginTemplateExtension
from .models import XGenericUri
from django.contrib.contenttypes.models import ContentType
from dcim.models import DeviceType


class DeviceTypeDeviceExtra(PluginTemplateExtension):
    """
    Template for displaying the XGenericURI inside the Detail-View of a Device.
    """
    models = ['dcim.devicetype']

    def right_page(self):
        deviceType = self.context.get('object')
        device_ct = ContentType.objects.get_for_model(DeviceType)
        pr = XGenericUri.objects.filter(content_type_id=device_ct.id, object_id=deviceType.id)
        return self.render('d3c/device_type_extra.html', extra_context={
            'device_type_extra': pr,
        })


template_extensions = [DeviceTypeDeviceExtra]
