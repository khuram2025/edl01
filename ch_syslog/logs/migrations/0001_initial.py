# Generated by Django 4.2.19 on 2025-02-20 11:23

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ParserTemplate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('vendor', models.CharField(choices=[('fortinet', 'Fortinet'), ('cisco', 'Cisco'), ('juniper', 'Juniper'), ('paloalto', 'Palo Alto'), ('other', 'Other')], max_length=50)),
                ('description', models.TextField(blank=True)),
                ('parsing_rules', models.JSONField(help_text='JSON configuration for parsing rules')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['vendor', 'name'],
            },
        ),
        migrations.CreateModel(
            name='ServiceStatus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(default='Syslog Receiver', editable=False, max_length=50)),
                ('is_running', models.BooleanField(default=False)),
                ('last_started', models.DateTimeField(blank=True, null=True)),
                ('last_stopped', models.DateTimeField(blank=True, null=True)),
                ('pid', models.IntegerField(blank=True, null=True)),
            ],
            options={
                'verbose_name_plural': 'Service Status',
            },
        ),
        migrations.CreateModel(
            name='Device',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(unique=True)),
                ('hostname', models.CharField(blank=True, max_length=255)),
                ('is_approved', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('description', models.TextField(blank=True)),
                ('last_log_received', models.DateTimeField(blank=True, null=True)),
                ('last_log_saved', models.DateTimeField(blank=True, null=True)),
                ('total_logs_received', models.IntegerField(default=0)),
                ('total_logs_saved', models.IntegerField(default=0)),
                ('last_log_message', models.TextField(blank=True)),
                ('parser_template', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='logs.parsertemplate')),
            ],
            options={
                'ordering': ['hostname', 'ip_address'],
            },
        ),
    ]
