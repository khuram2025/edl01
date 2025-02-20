from django.contrib import admin
from django.utils import timezone
from django.template.response import TemplateResponse
from django.urls import path
from .models import Device, ServiceStatus, ParserTemplate, TrafficLog

@admin.register(ParserTemplate)
class ParserTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'vendor', 'description', 'created_at', 'updated_at')
    list_filter = ('vendor',)
    search_fields = ('name', 'description')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'hostname', 'is_approved', 'parser_template', 'parser_template_display', 'last_log_status', 'total_logs', 'created_at')
    list_filter = ('is_approved', 'parser_template')
    search_fields = ('ip_address', 'hostname', 'description', 'last_log_message')
    ordering = ('hostname', 'ip_address')
    list_editable = ('is_approved', 'parser_template')
    readonly_fields = ('last_log_received', 'last_log_saved', 'total_logs_received', 
                      'total_logs_saved', 'last_log_message', 'created_at', 'updated_at')

    def parser_template_display(self, obj):
        if obj.parser_template:
            return f"{obj.parser_template.vendor} - {obj.parser_template.name}"
        return "No template"
    parser_template_display.short_description = 'Template Details'

    def last_log_status(self, obj):
        if not obj.last_log_received:
            return "No logs received"
        return f"Last received: {obj.last_log_received.strftime('%Y-%m-%d %H:%M:%S')}"
    last_log_status.short_description = 'Last Log Status'

    def total_logs(self, obj):
        return f"{obj.total_logs_saved}/{obj.total_logs_received} (saved/received)"
    total_logs.short_description = 'Total Logs'

    fieldsets = (
        (None, {
            'fields': ('ip_address', 'hostname', 'is_approved', 'parser_template', 'description')
        }),
        ('Log Statistics', {
            'fields': ('last_log_received', 'last_log_saved', 'total_logs_received', 
                      'total_logs_saved', 'last_log_message'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(ServiceStatus)
class ServiceStatusAdmin(admin.ModelAdmin):
    list_display = ('name', 'status_display', 'last_started', 'last_stopped', 'pid')
    readonly_fields = ('name', 'is_running', 'last_started', 'last_stopped', 'pid')
    change_list_template = 'admin/service_status_change_list.html'

    def status_display(self, obj):
        return 'Running' if obj.is_process_running() else 'Stopped'
    status_display.short_description = 'Status'

    def has_add_permission(self, request):
        # Only allow one instance
        return not ServiceStatus.objects.exists()

    def has_delete_permission(self, request, obj=None):
        # Prevent deletion
        return False

    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('control/', self.admin_site.admin_view(self.service_control_view), name='service-control'),
        ]
        return custom_urls + urls

    def service_control_view(self, request):
        service = ServiceStatus.objects.first()
        if not service:
            service = ServiceStatus.objects.create()

        if 'start' in request.POST:
            if service.start_service():
                service.last_started = timezone.now()
                service.save()
                self.message_user(request, 'Service started successfully')
            else:
                self.message_user(request, 'Failed to start service', level='ERROR')

        elif 'stop' in request.POST:
            if service.stop_service():
                service.last_stopped = timezone.now()
                service.save()
                self.message_user(request, 'Service stopped successfully')
            else:
                self.message_user(request, 'Failed to stop service', level='ERROR')

        elif 'restart' in request.POST:
            if service.restart_service():
                service.last_started = timezone.now()
                service.save()
                self.message_user(request, 'Service restarted successfully')
            else:
                self.message_user(request, 'Failed to restart service', level='ERROR')

        context = dict(
            self.admin_site.each_context(request),
            service=service,
        )
        return TemplateResponse(request, 'admin/service_status.html', context)

@admin.register(TrafficLog)
class TrafficLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'source_ip', 'destination_ip', 'protocol', 'action', 'application', 'firewall_name')
    list_filter = ('action', 'protocol', 'firewall_name', 'app_category')
    search_fields = ('source_ip', 'destination_ip', 'application', 'firewall_name', 'rule_name')
    readonly_fields = ('log_id', 'timestamp', 'start_time', 'end_time')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('log_id', 'timestamp', 'start_time', 'end_time', 'action')
        }),
        ('Network Details', {
            'fields': ('source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol')
        }),
        ('Traffic Statistics', {
            'fields': ('bytes_sent', 'bytes_received', 'packets_sent', 'packets_received', 'sent_pkt', 'rcvd_pkt'),
            'classes': ('collapse',)
        }),
        ('Application Info', {
            'fields': ('application', 'app_category', 'app_subcategory', 'category'),
            'classes': ('collapse',)
        }),
        ('Security', {
            'fields': ('severity', 'firewall_name', 'rule_name', 'session_id'),
            'classes': ('collapse',)
        })
    )
