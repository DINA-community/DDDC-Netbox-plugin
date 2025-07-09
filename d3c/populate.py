"""
    This file provides functionality to initialize the D3C-Plugin's Device Roles and default Manufacturers,
    Devices, and Device Types with the value 'Unspecified.'
    This is done by parsing the YAML files located in 'd3c/data/repo'.
"""
import yaml
import os
from glob import glob
from re import sub as re_sub


def get_value(key, data):
    if key in data.keys():
        return data[key]
    else:
        return None


class REPO:
    """
    This class parses the YAML files located in 'd3c/data/repo'.
    """

    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.cwd = os.getcwd()
        self.yaml_extensions = ['yaml', 'yml']

    def slug_format(self, name):
        return re_sub(r'\W+', '-', name.lower())

    def get_relative_path(self):
        return self.repo_path

    def get_absolute_path(self):
        return os.path.join(self.cwd, self.repo_path)

    def get_devices_path(self):
        return os.path.join(self.get_absolute_path(), 'device-types/')

    def get_roles_path(self):
        return os.path.join(self.get_absolute_path(), 'device-roles/')

    def get_sites_path(self):
        return os.path.join(self.get_absolute_path(), 'sites/')

    def get_devices(self, base_path, vendors: list = None):
        files = []
        discovered_vendors = []
        vendor_dirs = os.listdir(base_path)

        for folder in [vendor for vendor in vendor_dirs if not vendors or vendor.casefold() in vendors]:
            if folder.casefold() != "testing":
                discovered_vendors.append({'name': folder,
                                           'slug': self.slug_format(folder)})
                for extension in self.yaml_extensions:
                    files.extend(glob(base_path + folder + f'/*.{extension}'))
        return files, discovered_vendors

    def get_roles(self, base_path):
        deviceRoles = []
        files = os.listdir(base_path)
        for x in files:
            deviceRoles.append(base_path + x)
        return deviceRoles

    def get_sites(self, base_path):
        sites = []
        files = os.listdir(base_path)
        for x in files:
            sites.append(base_path + x)
        return sites

    def parse_files(self, files: list, slugs: list = None):
        deviceTypes = []
        for file in files:
            with open(file, 'r') as stream:
                try:
                    data = yaml.safe_load(stream)
                except yaml.YAMLError as excep:
                    self.handle.verbose_log(excep)
                    continue
                manufacturer = data['manufacturer']
                data['manufacturer'] = {
                    'name': manufacturer, 'slug': self.slug_format(manufacturer)}

                # Save file location to resolve any relative paths for images
                data['src'] = file

            if slugs and True not in [True if s.casefold() in data['slug'].casefold() else False for s in slugs]:
                handle.verbose_log(f"Skipping {data['model']}")
                continue

            deviceTypes.append(data)
        return deviceTypes

    def parse_roles(self, files: list, slugs: list = None):
        deviceRoles = []
        for file in files:
            print(file)
            with open(file, 'r') as stream:
                try:
                    data = yaml.safe_load(stream)
                except yaml.YAMLError as excep:
                    self.handle.verbose_log(excep)
                    continue
            deviceRoles.append(data)
        return deviceRoles

    def parse_sites(self, files: list, slugs: list = None):
        sites = []
        for file in files:
            print(file)
            with open(file, 'r') as stream:
                try:
                    data = yaml.safe_load(stream)
                except yaml.YAMLError as excep:
                    self.handle.verbose_log(excep)
                    continue
            sites.append(data)
        return sites

    def start(self):
        from dcim.models import DeviceRole, DeviceType, Manufacturer, Site
        from django.db.models import Q
        files, vendors = self.get_devices(self.get_devices_path())
        for x in vendors:
            name = get_value('name', x)
            slug = get_value('slug', x)
            manufacturer = Manufacturer.objects.filter(Q(name=name) | Q(slug=slug))
            if not manufacturer.exists():
                manufacturer, created = Manufacturer.objects.get_or_create(name=name, slug=slug)

        device_types = self.parse_files(files)
        for x in device_types:
            manufacturer = get_value('name', get_value('manufacturer', x))
            model = get_value('model', x)
            slug = get_value('slug', x)
            device_family = get_value('device_family', x)
            article_number = get_value('article_number', x)
            manufacturer_obj = Manufacturer.objects.get(name=manufacturer)
            dt = DeviceType.objects.filter(model=model, manufacturer=manufacturer_obj, slug=slug, u_height=1)
            if not dt.exists():
                device_type, created = DeviceType.objects.get_or_create(model=model, manufacturer=manufacturer_obj,
                                                                        slug=slug, u_height=1)
                device_type.custom_field_data["device_family"] = device_family
                device_type.custom_field_data["article_number"] = article_number
                device_type.save()

        roles = self.parse_roles(self.get_roles(self.get_roles_path()))
        for x in roles:
            name = get_value('name', x)
            slug = get_value('slug', x)
            description = get_value('description', x)
            dr = DeviceRole.objects.filter(Q(name=name) | Q(slug=slug))
            if not dr.exists():
                devicerole, created = DeviceRole.objects.get_or_create(name=name, slug=slug, description=description)

        sites = self.parse_sites(self.get_sites(self.get_sites_path()))
        for x in sites:
            name = get_value('name', x)
            status = get_value('status', x)
            slug = get_value('slug', x)
            dr = Site.objects.filter(Q(name=name) | Q(slug=slug))
            if not dr.exists():
                site, created = Site.objects.get_or_create(name=name, status=status, slug=slug)
