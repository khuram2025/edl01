import socketserver
import datetime
import os
from django.core.management.base import BaseCommand
from logs.models import TrafficLog
from django.utils.dateparse import parse_datetime
from django.utils import timezone
import logging

logger = logging.getLogger('syslog_receiver')

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            data = bytes.decode(self.request[0].strip())
            socket = self.request[1]
            client_ip = self.client_address[0]

            print(f"Received from {client_ip}: {data}")
            logger.error(f"Received from {client_ip}: {data}")

            log_data = self.parse_fortinet_message(data)

            if log_data:
                TrafficLog.objects.create(
                    timestamp=log_data.get('timestamp'),
                    date=log_data.get('date'),
                    time=log_data.get('time'),
                    source_ip=log_data.get('srcip'),
                    destination_ip=log_data.get('dstip'),
                    source_port=log_data.get('srcport'),
                    destination_port=log_data.get('dstport'),
                    protocol=log_data.get('proto'),
                    action=log_data.get('action'),
                    bytes_sent=log_data.get('sentbyte'),
                    bytes_received=log_data.get('rcvdbyte'),
                    packets_sent=log_data.get('sentpkt'),
                    packets_received=log_data.get('rcvdpkt'),
                    session_id=log_data.get('sessionid'),
                    application=log_data.get('app'),
                    app_category=log_data.get('appcat'),
                    severity=log_data.get('level'),
                    firewall_name=log_data.get('devname'),
                    rule_name=log_data.get('policyid'),
                    interface_in=log_data.get('srcintf'),
                    interface_out=log_data.get('dstintf'),
                    country_source=log_data.get('srccountry'),
                    country_destination=log_data.get('dstcountry'),
                    nat_source_ip=log_data.get('transip'),
                    nat_source_port=log_data.get('transport'),
                    duration=log_data.get('duration'),
                    src_zone=log_data.get('srcintfrole'),
                    dst_zone=log_data.get('dstintfrole'),
                    policy_uuid=log_data.get('poluuid'),
                    misc_field1=data
                )
                print(f"Saved to DB: {log_data}")
                logger.error(f"Saved to DB: {log_data}")
            else:
                print(f"Failed to parse from {client_ip}: {data}")
                logger.error(f"Failed to parse from {client_ip}: {data}")

        except Exception as e:
            logger.error(f"Error processing message: {e}")
            print(f"Error processing message: {e}")

    def parse_fortinet_message(self, message):
        try:
            fields = message.split()
            log_data = {}

            for field in fields:
                if '=' in field:
                    key, value = field.split('=', 1)
                    key = key.strip()
                    # Remove the <189> prefix if it exists
                    if key.startswith('<189>'):
                        key = key[5:]
                    value = value.strip('"')
                    log_data[key] = value

            # Combine date and time to timestamp
            if 'date' in log_data and 'time' in log_data:
                timestamp_str = f"{log_data['date']} {log_data['time']}"
                try:
                    log_data['timestamp'] = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                except ValueError:
                    log_data['timestamp'] = None

            # Convert numeric fields to integers/floats
            numeric_fields = {'srcport', 'dstport', 'proto', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt', 'sessionid', 'policyid', 'duration', 'appid'}
            for field in numeric_fields:
                if field in log_data:
                    try:
                        log_data[field] = int(log_data[field]) if field != 'duration' else float(log_data[field])
                    except ValueError:
                        log_data[field] = None

            return log_data

        except Exception as e:
            logger.error(f"Failed to parse message: {str(e)}")
            return None

class Command(BaseCommand):
    help = 'Starts a syslog receiver on port 514'

    def add_arguments(self, parser):
        parser.add_argument(
            '--port',
            type=int,
            default=1514,
            help='Port to listen on (default: 1514)'
        )

    def handle(self, *args, **kwargs):
        port = kwargs['port']
        host = '0.0.0.0'

        self.stdout.write(self.style.SUCCESS(f"Starting syslog receiver on {host}:{port}"))

        with socketserver.UDPServer((host, port), SyslogUDPHandler) as server:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                self.stdout.write(self.style.SUCCESS("Shutting down syslog receiver..."))
