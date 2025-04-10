import django.contrib.postgres.fields
import django.db.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('d3c', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='DeviceFinding',
            name='ip_netmask',
            field=models.CharField(blank=True, max_length=1000, null=True),
        ),
    ]
