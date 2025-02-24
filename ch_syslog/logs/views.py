from django.shortcuts import render
from django.views.generic import ListView
from django.core.paginator import Paginator
from datetime import datetime, timedelta
from django.conf import settings
import pytz
import logging
import re
from django.utils import timezone
import json
import sys
from .models import TrafficLog
from django.db.models import F, Value, CharField, Q
from django.db.models.functions import Concat

# Set up logger for this module
logger = logging.getLogger(__name__)

# Create your views here.

class SyslogListView(ListView):
    template_name = 'logs/syslog_list.html'
    context_object_name = 'logs'
    paginate_by = 50

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        try:
            # Use http:// scheme explicitly
            es_url = f"http://{settings.ELASTICSEARCH_HOST}:{settings.ELASTICSEARCH_PORT}"
            self.es = Elasticsearch([es_url])
        except Exception as e:
            logger.error(f"Failed to initialize Elasticsearch connection: {str(e)}")
            self.es = None

    def get_queryset(self):
        if not self.es:
            logger.error("Elasticsearch client is not initialized")
            return []

        # Get query parameters
        page = self.request.GET.get('page', 1)
        search_query = self.request.GET.get('q', '')
        date_filter = self.request.GET.get('date', '')
        
        # Calculate pagination
        start = (int(page) - 1) * self.paginate_by
        
        # Build Elasticsearch query
        query = {
            "bool": {
                "must": []
            }
        }
        
        # Add search term if provided
        if search_query:
            query["bool"]["must"].append({
                "multi_match": {
                    "query": search_query,
                    "fields": ["message", "device_hostname", "device_ip", "log_source_ip"]
                }
            })
            
        # Add date filter if provided
        if date_filter:
            try:
                filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
                index_name = f"syslog-{filter_date.strftime('%Y.%m.%d')}"
            except ValueError:
                # If invalid date, use all indices
                index_name = "syslog-*"
        else:
            index_name = "syslog-*"
        
        try:
            # Execute Elasticsearch search
            response = self.es.search(
                index=index_name,
                body={
                    "query": query,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "from": start,
                    "size": self.paginate_by
                }
            )
            
            # Process results
            logs = []
            for hit in response['hits']['hits']:
                source = hit['_source']
                logs.append({
                    'timestamp': source.get('timestamp'),
                    'received_at': source.get('received_at'),
                    'host': source.get('device_hostname'),
                    'device_ip': source.get('device_ip'),
                    'log_source_ip': source.get('log_source_ip'),
                    'log_destination_ip': source.get('log_destination_ip'),
                    'message': source.get('message'),
                    'raw_message': source.get('raw_message'),
                    'device_id': source.get('device_id'),
                    'parser_template': source.get('parser_template'),
                    'parsed_vendor': source.get('parsed_vendor'),
                    'parsed_fields': source.get('parsed_fields', {})
                })
            
            return logs
        except Exception as e:
            logger.error(f"Elasticsearch error: {str(e)}")
            return []

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            # Add date filter options
            context['dates'] = self._get_available_dates()
            context['search_query'] = self.request.GET.get('q', '')
            context['selected_date'] = self.request.GET.get('date', '')
        except Exception as e:
            logger.error(f"Error getting context data: {str(e)}")
            context['dates'] = []
            context['search_query'] = ''
            context['selected_date'] = ''
        return context
    
    def _get_available_dates(self):
        try:
            indices = self.es.cat.indices(index="syslog-*", h="index", format="json")
            dates = []
            for idx in indices:
                try:
                    # Extract date from index name (format: syslog-YYYY.MM.DD)
                    date_str = idx['index'].split('-')[1]
                    date_obj = datetime.strptime(date_str, '%Y.%m.%d').date()
                    dates.append(date_obj.strftime('%Y-%m-%d'))
                except (IndexError, ValueError):
                    continue
            return sorted(dates, reverse=True)
        except Exception as e:
            logger.error(f"Error getting available dates: {str(e)}")
            return []

class LogListView(ListView):
    template_name = 'logs/log_list.html'
    context_object_name = 'logs'
    paginate_by = 50
    model = TrafficLog
    ordering = ['-timestamp']  # Show newest logs first

    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Annotate queryset with formatted date and time
        queryset = queryset.annotate(
            formatted_date=F('timestamp__date'),
            formatted_time=F('timestamp__time')
        )
        
        # Apply filters based on request parameters
        action = self.request.GET.get('action')
        source_ips = self.request.GET.getlist('source_ip')
        dest_ips = self.request.GET.getlist('dest_ip')
        dest_port = self.request.GET.get('dest_port')
        date_range = self.request.GET.get('date_range')

        # Log filter parameters for debugging
        logger.info(f"Filter parameters: action={action}, source_ips={source_ips}, dest_ips={dest_ips}, dest_port={dest_port}, date_range={date_range}")

        # Source IP filter
        if source_ips:
            source_ip_conditions = Q()
            for ip in source_ips:
                source_ip_conditions |= Q(source_ip=ip)
            queryset = queryset.filter(source_ip_conditions)

        # Destination IP filter
        if dest_ips:
            dest_ip_conditions = Q()
            for ip in dest_ips:
                dest_ip_conditions |= Q(destination_ip=ip)
            queryset = queryset.filter(dest_ip_conditions)

        # Destination Port filter
        if dest_port:
            queryset = queryset.filter(destination_port=dest_port)

        # Action filter
        if action:
            queryset = queryset.filter(action__iexact=action)

        # Date range filter
        now = timezone.now()
        if date_range:
            if date_range == 'custom':
                from_date = self.request.GET.get('from_date')
                from_time = self.request.GET.get('from_time', '00:00')
                to_date = self.request.GET.get('to_date')
                to_time = self.request.GET.get('to_time', '23:59')
                
                if from_date:
                    try:
                        from_datetime = datetime.strptime(f"{from_date} {from_time}", '%Y-%m-%d %H:%M')
                        to_datetime = datetime.strptime(f"{to_date} {to_time}", '%Y-%m-%d %H:%M') if to_date else now
                        
                        # Convert to timezone-aware datetime
                        from_datetime = timezone.make_aware(from_datetime)
                        to_datetime = timezone.make_aware(to_datetime)
                        
                        # Validate dates are not in the future
                        if from_datetime > now or to_datetime > now:
                            logger.warning(f"Future date selected: from={from_datetime}, to={to_datetime}, now={now}")
                            return queryset.none()
                        
                        queryset = queryset.filter(timestamp__gte=from_datetime, timestamp__lte=to_datetime)
                    except ValueError as e:
                        logger.error(f"Date parsing error: {e}")
                        return queryset.none()
            elif date_range == 'today':
                today = now.date()
                queryset = queryset.filter(timestamp__date=today)
            elif date_range == 'yesterday':
                yesterday = (now - timedelta(days=1)).date()
                queryset = queryset.filter(timestamp__date=yesterday)
            elif date_range == 'last_7_days':
                seven_days_ago = now - timedelta(days=7)
                queryset = queryset.filter(timestamp__gte=seven_days_ago)
            elif date_range == 'last_30_days':
                thirty_days_ago = now - timedelta(days=30)
                queryset = queryset.filter(timestamp__gte=thirty_days_ago)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'source_ips': self.request.GET.getlist('source_ip'),
            'dest_ips': self.request.GET.getlist('dest_ip'),
            'dest_port': self.request.GET.get('dest_port', ''),
            'action': self.request.GET.get('action', ''),
            'date_range': self.request.GET.get('date_range', ''),
            'from_date': self.request.GET.get('from_date', ''),
            'from_time': self.request.GET.get('from_time', ''),
            'to_date': self.request.GET.get('to_date', ''),
            'to_time': self.request.GET.get('to_time', ''),
            'today_date': timezone.now().strftime('%Y-%m-%d')
        })
        return context

class TrafficLogListView(ListView):
    model = TrafficLog
    template_name = 'logs/traffic_log_list.html'
    context_object_name = 'logs'
    paginate_by = 25
    ordering = ['-timestamp']

    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Get filter parameters
        source_ip = self.request.GET.get('source_ip')
        dest_ip = self.request.GET.get('dest_ip')
        action = self.request.GET.get('action')
        firewall = self.request.GET.get('firewall')
        
        # Apply filters if they exist
        if source_ip:
            queryset = queryset.filter(source_ip=source_ip)
        if dest_ip:
            queryset = queryset.filter(destination_ip=dest_ip)
        if action:
            queryset = queryset.filter(action=action)
        if firewall:
            queryset = queryset.filter(firewall_name=firewall)

        # Annotate the queryset with formatted timestamp
        queryset = queryset.annotate(
            formatted_time=Concat(
                F('date'),
                Value(' '),
                F('time'),
                output_field=CharField()
            )
        )
            
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add filter values to context
        context['source_ip'] = self.request.GET.get('source_ip', '')
        context['dest_ip'] = self.request.GET.get('dest_ip', '')
        context['action'] = self.request.GET.get('action', '')
        context['firewall'] = self.request.GET.get('firewall', '')
        
        # Add unique values for dropdowns
        context['actions'] = TrafficLog.objects.values_list('action', flat=True).distinct()
        context['firewalls'] = TrafficLog.objects.values_list('firewall_name', flat=True).distinct()
        
        return context
