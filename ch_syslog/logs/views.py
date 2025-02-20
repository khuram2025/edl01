from django.shortcuts import render
from django.views.generic import ListView
from django.core.paginator import Paginator
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
from django.conf import settings
import pytz
import logging
import re
from django.utils import timezone
import json
import sys
from .models import TrafficLog
from django.db.models import F, Value, CharField
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._total_count = 0
        self.error_message = None
        try:
            es_url = f"http://{settings.ELASTICSEARCH_HOST}:{settings.ELASTICSEARCH_PORT}"
            self.es = Elasticsearch([es_url])
            # Test connection
            if not self.es.ping():
                self.error_message = "Could not connect to Elasticsearch server"
                logger.error(self.error_message)
                self.es = None
            else:
                logger.info("Successfully connected to Elasticsearch")
                # Get index mapping to check available fields
                try:
                    mapping = self.es.indices.get_mapping(index=settings.ELASTICSEARCH_INDEX)
                    logger.info(f"Index mapping: {json.dumps(mapping)}")
                except Exception as e:
                    logger.warning(f"Could not get index mapping: {str(e)}")
        except Exception as e:
            self.error_message = f"Failed to initialize Elasticsearch connection: {str(e)}"
            logger.error(self.error_message)
            self.es = None

    def _is_valid_ip_or_cidr(self, ip_or_cidr):
        try:
            # Check if it's a CIDR notation
            if '/' in ip_or_cidr:
                network = ip_or_cidr.split('/')
                if len(network) != 2:
                    return False
                ip, bits = network
                if not 0 <= int(bits) <= 32:
                    return False
            # IP address validation
            parts = ip_or_cidr.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False
        return True

    def get_queryset(self):
        if not self.es:
            logger.error("Elasticsearch client is not initialized")
            return []

        page_size = 50
        page = self.request.GET.get('page', 1)
        try:
            page = int(page)
        except ValueError:
            page = 1

        # Build Elasticsearch query
        query = {
            "bool": {
                "must": [],
                "filter": []
            }
        }

        # Apply filters based on request parameters
        action = self.request.GET.get('action')
        source_ips = self.request.GET.getlist('source_ip')
        dest_ips = self.request.GET.getlist('dest_ip')
        dest_port = self.request.GET.get('dest_port')
        date_range = self.request.GET.get('date_range')

        # Log filter parameters for debugging
        logger.info(f"Filter parameters: action={action}, source_ips={source_ips}, dest_ips={dest_ips}, dest_port={dest_port}, date_range={date_range}")

        # Source IP filter (multiple, including subnets)
        if source_ips:
            source_ip_query = {
                "bool": {
                    "should": []
                }
            }
            
            for ip in source_ips:
                if not self._is_valid_ip_or_cidr(ip):
                    logger.warning(f"Invalid source IP or CIDR: {ip}")
                    continue
                    
                if '/' in ip:
                    # This is a subnet
                    source_ip_query['bool']['should'].append({
                        "ip_range": {
                            "parsed_fields.srcip": {
                                "cidr": ip
                            }
                        }
                    })
                else:
                    # This is a single IP
                    source_ip_query['bool']['should'].append({
                        "term": {
                            "parsed_fields.srcip.keyword": ip
                        }
                    })
            
            if source_ip_query['bool']['should']:
                source_ip_query['bool']['minimum_should_match'] = 1
                query['bool']['must'].append(source_ip_query)

        # Destination IP filter (multiple, including subnets)
        if dest_ips:
            dest_ip_query = {
                "bool": {
                    "should": []
                }
            }
            
            for ip in dest_ips:
                if not self._is_valid_ip_or_cidr(ip):
                    logger.warning(f"Invalid destination IP or CIDR: {ip}")
                    continue
                    
                if '/' in ip:
                    # This is a subnet
                    dest_ip_query['bool']['should'].append({
                        "ip_range": {
                            "parsed_fields.dstip": {
                                "cidr": ip
                            }
                        }
                    })
                else:
                    # This is a single IP
                    dest_ip_query['bool']['should'].append({
                        "term": {
                            "parsed_fields.dstip.keyword": ip
                        }
                    })
            
            if dest_ip_query['bool']['should']:
                dest_ip_query['bool']['minimum_should_match'] = 1
                query['bool']['must'].append(dest_ip_query)

        # Destination Port filter
        if dest_port:
            query['bool']['must'].append({
                "term": {
                    "parsed_fields.dstport": dest_port
                }
            })

        # Action filter
        if action:
            query['bool']['must'].append({
                "term": {
                    "parsed_fields.action.keyword": action.lower()
                }
            })

        # Date range filter
        now = timezone.now()
        index_pattern = settings.ELASTICSEARCH_INDEX
        if date_range:
            date_filter = None
            if date_range == 'custom':
                from_date = self.request.GET.get('from_date')
                from_time = self.request.GET.get('from_time', '00:00')
                to_date = self.request.GET.get('to_date')
                to_time = self.request.GET.get('to_time', '23:59')
                
                if from_date:
                    try:
                        from_datetime = datetime.strptime(f"{from_date} {from_time}", '%Y-%m-%d %H:%M')
                        to_datetime = datetime.strptime(f"{to_date} {to_time}", '%Y-%m-%d %H:%M') if to_date else now
                        
                        # Convert to timezone-aware datetime for comparison
                        from_datetime = timezone.make_aware(from_datetime)
                        to_datetime = timezone.make_aware(to_datetime)
                        
                        # Validate dates are not in the future
                        if from_datetime > now or to_datetime > now:
                            self.error_message = "Cannot select future dates. Please select dates up to the current date and time."
                            logger.warning(f"Future date selected: from={from_datetime}, to={to_datetime}, now={now}")
                            return []
                        
                        date_filter = {
                            "gte": from_datetime.isoformat(),
                            "lte": to_datetime.isoformat()
                        }
                        # Set index pattern to include all dates in range
                        index_pattern = f"syslog-{from_datetime.strftime('%Y.%m')}-*"
                    except ValueError as e:
                        self.error_message = "Invalid date format. Please use the date picker to select valid dates."
                        logger.error(f"Error parsing custom date range: {str(e)}")
                        return []
            elif date_range == 'today':
                date_filter = {"gte": now.replace(hour=0, minute=0, second=0).isoformat()}
                index_pattern = f"syslog-{now.strftime('%Y.%m.%d')}"
            elif date_range == 'yesterday':
                yesterday = now - timedelta(days=1)
                date_filter = {
                    "gte": yesterday.replace(hour=0, minute=0, second=0).isoformat(),
                    "lt": now.replace(hour=0, minute=0, second=0).isoformat()
                }
                index_pattern = f"syslog-{yesterday.strftime('%Y.%m.%d')}"
            elif date_range == 'last_7_days':
                date_filter = {"gte": (now - timedelta(days=7)).isoformat()}
                index_pattern = f"syslog-{(now - timedelta(days=7)).strftime('%Y.%m')}-*"
            elif date_range == 'last_30_days':
                date_filter = {"gte": (now - timedelta(days=30)).isoformat()}
                index_pattern = f"syslog-{(now - timedelta(days=30)).strftime('%Y.%m')}-*"
            
            if date_filter:
                query['bool']['must'].append({
                    "range": {
                        "timestamp": date_filter
                    }
                })

        try:
            # First, check if the index exists
            if not self.es.indices.exists(index=index_pattern):
                self.error_message = f"Index {index_pattern} does not exist"
                logger.error(self.error_message)
                return []

            # Log the final query for debugging
            logger.info(f"Elasticsearch query: {json.dumps(query)}")
            logger.info(f"Using index pattern: {index_pattern}")

            # Execute search
            search_results = self.es.search(
                index=index_pattern,
                body={
                    "query": query,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "from": (page - 1) * page_size,
                    "size": page_size,
                    "track_total_hits": True
                }
            )

            self._total_count = search_results['hits']['total']['value']
            logger.info(f"Total hits: {self._total_count}")

            if self._total_count == 0:
                self.error_message = "No logs match your current filters"
                logger.info("No results found")
                return []

            logs = []
            for hit in search_results['hits']['hits']:
                source = hit['_source']
                parsed_fields = source.get('parsed_fields', {})
                
                # Extract timestamp from the message field
                message = source.get('message', '')
                event_date = ''
                event_time = ''
                
                # Try to get timestamp from parsed_fields first
                if parsed_fields.get('time'):
                    try:
                        msg_time = parsed_fields.get('time')
                        # If time is already a datetime string, parse it directly
                        if isinstance(msg_time, str):
                            dt = datetime.fromisoformat(msg_time.replace('Z', '+00:00'))
                        else:
                            # If it's a timestamp, convert it
                            dt = datetime.fromtimestamp(msg_time)
                        event_date = dt.strftime('%Y-%m-%d')
                        event_time = dt.strftime('%H:%M:%S')
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Error parsing time from parsed_fields: {e}")
                
                # If no valid time found in parsed_fields, try to extract from message
                if not event_time and message:
                    try:
                        # Try to match format: date=YYYY-MM-DD time=HH:MM:SS
                        date_match = re.search(r'date=(\d{4}-\d{2}-\d{2})', message)
                        time_match = re.search(r'time=(\d{2}:\d{2}:\d{2})', message)
                        
                        if date_match and time_match:
                            date_str = date_match.group(1)
                            time_str = time_match.group(1)
                            dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                            event_date = dt.strftime('%Y-%m-%d')
                            event_time = dt.strftime('%H:%M:%S')
                        else:
                            # Fallback to common syslog time format: MMM DD HH:MM:SS
                            time_match = re.search(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', message)
                            if time_match:
                                time_str = time_match.group(1)
                                # Add current year since syslog format doesn't include it
                                current_year = datetime.now().year
                                dt = datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H:%M:%S")
                                event_date = dt.strftime('%Y-%m-%d')
                                event_time = dt.strftime('%H:%M:%S')
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Error extracting time from message: {e}")
                        logger.warning(f"Message content: {message}")

                log_entry = {
                    'message': message,
                    'event_date': event_date,
                    'event_time': event_time,
                    'device_ip': source.get('device_ip', '-'),
                    'srcip': parsed_fields.get('srcip', '-'),
                    'srcintf': parsed_fields.get('srcintf', '-'),
                    'dstip': parsed_fields.get('dstip', '-'),
                    'dstintf': parsed_fields.get('dstintf', '-'),
                    'dstport': parsed_fields.get('dstport', '-'),
                    'action': parsed_fields.get('action', '-')
                }
                logs.append(log_entry)

            return logs

        except Exception as e:
            self.error_message = f"Error retrieving logs: {str(e)}"
            logger.error(f"Elasticsearch error: {str(e)}")
            logger.error(f"Query that caused the error: {json.dumps(query)}")
            return []

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'total_count': self._total_count,
            'error_message': getattr(self, 'error_message', None),
            'source_ips': self.request.GET.getlist('source_ip'),
            'dest_ips': self.request.GET.getlist('dest_ip'),
            'dest_port': self.request.GET.get('dest_port', ''),
            'action': self.request.GET.get('action', ''),
            'date_range': self.request.GET.get('date_range', ''),
            'from_date': self.request.GET.get('from_date', ''),
            'from_time': self.request.GET.get('from_time', ''),
            'to_date': self.request.GET.get('to_date', ''),
            'to_time': self.request.GET.get('to_time', ''),
            'today_date': datetime.now().strftime('%Y-%m-%d')
        })
        return context

    def get_paginator(self, queryset, per_page, orphans=0, allow_empty_first_page=True):
        # Create a custom paginator that uses the total count from Elasticsearch
        class ElasticsearchPaginator:
            def __init__(self, object_list, per_page, total_count):
                self.object_list = object_list
                self.per_page = per_page
                self.total_count = total_count

            @property
            def count(self):
                return self.total_count

            @property
            def num_pages(self):
                return max(1, (self.total_count + self.per_page - 1) // self.per_page)

            def page(self, number):
                # Simple page class to match Django's expectations
                class Page:
                    def __init__(self, object_list, number, paginator):
                        self.object_list = object_list
                        self.number = number
                        self.paginator = paginator

                    def has_next(self):
                        return self.number < self.paginator.num_pages

                    def has_previous(self):
                        return self.number > 1

                    def has_other_pages(self):
                        return self.has_next() or self.has_previous()

                    def next_page_number(self):
                        return self.number + 1

                    def previous_page_number(self):
                        return self.number - 1

                    def start_index(self):
                        return (self.number - 1) * self.paginator.per_page + 1

                    def end_index(self):
                        return min(self.start_index() + len(self.object_list) - 1, self.paginator.count)

                return Page(queryset, int(number), self)

        return ElasticsearchPaginator(queryset, per_page, self._total_count)

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
