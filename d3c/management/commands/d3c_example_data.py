"""
Import the example data shipped with d3c (device types, device roles, sites) into NetBox.
"""
import os

from dcim.models import DeviceRole, DeviceType, Manufacturer, Site
from django.core.management.base import BaseCommand
from django.db import transaction

from d3c.populate import REPO


class Command(BaseCommand):
    """ Custom command to import example data """

    help = """
        Import the D3C example data (manufacturers, device types, device roles and sites).
        Existing objects are left untouched.
        Can be run repeatedly.
    """

    def add_arguments(self, parser):
        """ Register the command's options. """
        parser.add_argument(
            '-n',
            '--dry-run',
            action='store_true',
            help="Only show what would be created",
        )

    def handle(self, *args, **options):
        models = (Manufacturer, DeviceType, DeviceRole, Site)
        before_counter = {model: model.objects.count() for model in models}

        repo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), 'data', 'repo')
        self.stdout.write(f"Importing example data from {repo_path}")

        if options['dry_run']:
            with transaction.atomic():
                REPO(repo_path).start()
                after_counter = {model: model.objects.count() for model in models}
                transaction.set_rollback(True)
        else:
            REPO(repo_path).start()
            after_counter = {model: model.objects.count() for model in models}

        # Show how many objects were imported per model
        for model in models:
            created = after_counter[model] - before_counter[model]
            self.stdout.write(
                f"  {model._meta.verbose_name_plural}: {created} created ({after_counter[model]} total)"
            )

        if options['dry_run']:
            self.stdout.write(self.style.WARNING("Dry run: no changes saved."))
        else:
            self.stdout.write(self.style.SUCCESS("Example data imported."))
