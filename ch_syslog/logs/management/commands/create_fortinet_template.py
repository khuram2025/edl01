from django.core.management.base import BaseCommand
from logs.models import ParserTemplate
import json

class Command(BaseCommand):
    help = 'Creates or updates the default Fortinet parser template'

    def handle(self, *args, **options):
        # Fortinet syslog parsing rules based on FortiOS 7.4.0 documentation
        fortinet_rules = {
            "fields": {
                "type": ["string", "Log type (traffic, event, virus, webfilter, etc.)"],
                "subtype": ["string", "Log subtype"],
                "level": ["string", "Severity level"],
                "vd": ["string", "Virtual domain name"],
                "date": ["string", "Date and time the log was recorded"],
                "time": ["string", "Time the log was recorded"],
                "devname": ["string", "Device name"],
                "devid": ["string", "Device ID"],
                "logid": ["string", "Log ID"],
                "status": ["string", "Status (success, failure, etc.)"],
                "policyid": ["integer", "Policy ID if available"],
                "sessionid": ["integer", "Session ID if available"],
                "srcip": ["ip", "Source IP address"],
                "srcport": ["integer", "Source port"],
                "srcintf": ["string", "Source interface"],
                "dstip": ["ip", "Destination IP address"],
                "dstport": ["integer", "Destination port"],
                "dstintf": ["string", "Destination interface"],
                "proto": ["integer", "Protocol number"],
                "action": ["string", "Action taken"],
                "service": ["string", "Service name"],
                "hostname": ["string", "Hostname"],
                "profile": ["string", "Security profile"],
                "duration": ["integer", "Session duration"],
                "sentbyte": ["integer", "Number of bytes sent"],
                "rcvdbyte": ["integer", "Number of bytes received"],
                "msg": ["string", "Message description"]
            },
            "patterns": {
                "kv_pair": r'(\w+)="([^"]*)"',  # Key-value pairs pattern
                "date_time": r'date=(\d{4}-\d{2}-\d{2}) time=(\d{2}:\d{2}:\d{2})'
            }
        }

        try:
            template, created = ParserTemplate.objects.update_or_create(
                vendor='fortinet',
                name='FortiOS 7.4.0 Default',
                defaults={
                    'description': 'Default parser template for FortiOS 7.4.0 syslog messages',
                    'parsing_rules': fortinet_rules
                }
            )

            if created:
                self.stdout.write(
                    self.style.SUCCESS('Successfully created Fortinet parser template')
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS('Successfully updated Fortinet parser template')
                )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Failed to create/update Fortinet parser template: {str(e)}')
            ) 