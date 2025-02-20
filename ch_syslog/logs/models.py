from django.db import models
import subprocess
import os
import signal
import psutil
import json

class ParserTemplate(models.Model):
    VENDOR_CHOICES = [
        ('fortinet', 'Fortinet'),
        ('cisco', 'Cisco'),
        ('juniper', 'Juniper'),
        ('paloalto', 'Palo Alto'),
        ('other', 'Other'),
    ]

    name = models.CharField(max_length=255, unique=True)
    vendor = models.CharField(max_length=50, choices=VENDOR_CHOICES)
    description = models.TextField(blank=True)
    parsing_rules = models.JSONField(help_text="JSON configuration for parsing rules")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.vendor} - {self.name}"

    def parse_message(self, raw_message):
        """
        Parse a raw syslog message according to the template rules
        Returns a dictionary of parsed fields
        """
        try:
            parsed_data = {
                'raw_message': raw_message,
                'parsed_fields': {}
            }
            
            # Apply parsing rules from the template
            rules = self.parsing_rules
            
            # Basic implementation - can be extended based on specific vendor needs
            if self.vendor == 'fortinet':
                # Split message into key-value pairs
                parts = raw_message.split()
                for part in parts:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        parsed_data['parsed_fields'][key] = value.strip('"')
            
            return parsed_data
        except Exception as e:
            return {
                'raw_message': raw_message,
                'parsing_error': str(e)
            }

    class Meta:
        ordering = ['vendor', 'name']

# Create your models here.

class Device(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True)
    is_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    description = models.TextField(blank=True)
    last_log_received = models.DateTimeField(null=True, blank=True)
    last_log_saved = models.DateTimeField(null=True, blank=True)
    total_logs_received = models.IntegerField(default=0)
    total_logs_saved = models.IntegerField(default=0)
    last_log_message = models.TextField(blank=True)
    parser_template = models.ForeignKey(ParserTemplate, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return f"{self.hostname} ({self.ip_address})"

    def update_log_received(self, message):
        from django.utils import timezone
        self.last_log_received = timezone.now()
        self.total_logs_received += 1
        self.last_log_message = message
        self.save()

    def update_log_saved(self):
        from django.utils import timezone
        self.last_log_saved = timezone.now()
        self.total_logs_saved += 1
        self.save()

    class Meta:
        ordering = ['hostname', 'ip_address']

class ServiceStatus(models.Model):
    PID_FILE = '/tmp/syslog_receiver.pid'
    
    name = models.CharField(max_length=50, default='Syslog Receiver', editable=False)
    is_running = models.BooleanField(default=False)
    last_started = models.DateTimeField(null=True, blank=True)
    last_stopped = models.DateTimeField(null=True, blank=True)
    pid = models.IntegerField(null=True, blank=True)

    class Meta:
        verbose_name_plural = "Service Status"

    def __str__(self):
        return f"{self.name} - {'Running' if self.is_running else 'Stopped'}"

    def save_pid(self, pid):
        with open(self.PID_FILE, 'w') as f:
            f.write(str(pid))
        self.pid = pid
        self.save()

    def read_pid(self):
        try:
            if os.path.exists(self.PID_FILE):
                with open(self.PID_FILE, 'r') as f:
                    return int(f.read().strip())
        except:
            return None
        return None

    def is_process_running(self):
        pid = self.read_pid()
        if pid:
            try:
                process = psutil.Process(pid)
                return process.is_running() and 'syslog_receiver' in ' '.join(process.cmdline())
            except:
                return False
        return False

    def start_service(self):
        if not self.is_process_running():
            cmd = f'sudo /home/net/django_project/venv/bin/python3 /home/net/django_project/ch_syslog/manage.py syslog_receiver'
            process = subprocess.Popen(cmd.split(), 
                                    stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE)
            self.save_pid(process.pid)
            self.is_running = True
            self.save()
            return True
        return False

    def stop_service(self):
        pid = self.read_pid()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                self.is_running = False
                self.pid = None
                if os.path.exists(self.PID_FILE):
                    os.remove(self.PID_FILE)
                self.save()
                return True
            except:
                return False
        return False

    def restart_service(self):
        self.stop_service()
        import time
        time.sleep(2)  # Wait for the service to stop
        return self.start_service()

    def save(self, *args, **kwargs):
        if not ServiceStatus.objects.exists() or self.pk:
            super().save(*args, **kwargs)
        else:
            raise Exception("Only one ServiceStatus instance is allowed")


from django.db import models

class TrafficLog(models.Model):
    log_id = models.CharField(max_length=255, null=True, blank=True)  # Unique identifier if provided by source
    timestamp = models.DateTimeField(null=True, blank=True)
    date = models.CharField(max_length=10, null=True, blank=True)  # Store raw date string
    time = models.CharField(max_length=8, null=True, blank=True)   # Store raw time string
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    source_port = models.PositiveIntegerField(null=True, blank=True)
    destination_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=20, null=True, blank=True)
    action = models.CharField(max_length=50, null=True, blank=True)
    bytes_sent = models.BigIntegerField(null=True, blank=True)
    bytes_received = models.BigIntegerField(null=True, blank=True)
    packets_sent = models.BigIntegerField(null=True, blank=True)
    packets_received = models.BigIntegerField(null=True, blank=True)
    sent_pkt = models.BigIntegerField(null=True, blank=True)  # Specific to Fortinet
    rcvd_pkt = models.BigIntegerField(null=True, blank=True)  # Specific to Fortinet
    session_id = models.CharField(max_length=100, null=True, blank=True)
    application = models.CharField(max_length=100, null=True, blank=True)
    app_category = models.CharField(max_length=100, null=True, blank=True)
    app_subcategory = models.CharField(max_length=100, null=True, blank=True)
    category = models.CharField(max_length=100, null=True, blank=True)
    severity = models.CharField(max_length=20, null=True, blank=True)
    firewall_name = models.CharField(max_length=100, null=True, blank=True)
    rule_name = models.CharField(max_length=100, null=True, blank=True)
    policy_id = models.IntegerField(null=True, blank=True)
    policy_uuid = models.CharField(max_length=100, null=True, blank=True)
    interface_in = models.CharField(max_length=100, null=True, blank=True)
    interface_out = models.CharField(max_length=100, null=True, blank=True)
    country_source = models.CharField(max_length=100, null=True, blank=True)
    country_destination = models.CharField(max_length=100, null=True, blank=True)
    nat_source_ip = models.GenericIPAddressField(null=True, blank=True)
    nat_destination_ip = models.GenericIPAddressField(null=True, blank=True)
    nat_source_port = models.PositiveIntegerField(null=True, blank=True)
    nat_destination_port = models.PositiveIntegerField(null=True, blank=True)
    duration = models.FloatField(null=True, blank=True)
    threat_name = models.CharField(max_length=255, null=True, blank=True)
    threat_id = models.CharField(max_length=100, null=True, blank=True)
    url = models.URLField(null=True, blank=True)
    user_name = models.CharField(max_length=100, null=True, blank=True)
    src_zone = models.CharField(max_length=100, null=True, blank=True)
    dst_zone = models.CharField(max_length=100, null=True, blank=True)
    src_interface = models.CharField(max_length=100, null=True, blank=True)
    dst_interface = models.CharField(max_length=100, null=True, blank=True)
    misc_field1 = models.TextField(null=True, blank=True)  # For future use
    misc_field2 = models.TextField(null=True, blank=True)  # For future use

    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['destination_ip']),
            models.Index(fields=['session_id']),
        ]

    def __str__(self):
        return f"TrafficLog {self.timestamp} {self.source_ip} -> {self.destination_ip}"
