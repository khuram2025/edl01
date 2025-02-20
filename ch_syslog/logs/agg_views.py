# logs/views.py
import json
import base64
import logging
from django.conf import settings
from django.views.generic import ListView
from django.utils import timezone
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class AggregatedLogsListView(ListView):
    template_name = 'logs/aggregated_logs.html'
    context_object_name = 'aggregated_logs'
    paginate_by = 20

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.es = None
        self.error_message = None
        try:
            es_url = f"http://{settings.ELASTICSEARCH_HOST}:{settings.ELASTICSEARCH_PORT}"
            self.es = Elasticsearch([es_url])
            if not self.es.ping():
                self.error_message = "Could not connect to Elasticsearch"
                logger.error(self.error_message)
                self.es = None
            else:
                logger.info("Connected to Elasticsearch")
        except Exception as e:
            self.error_message = f"Elasticsearch Error: {str(e)}"
            logger.error(self.error_message)
            self.es = None

    def get_queryset(self):
        logger.info("Starting get_queryset method")
        
        if not self.es:
            logger.error("Elasticsearch client is not initialized")
            return []

        try:
            # Get page number from request
            page = self.request.GET.get('page', '1')
            try:
                page = int(page)
                if page < 1:
                    page = 1
            except (TypeError, ValueError):
                page = 1

            # Build the Elasticsearch query with filters
            query = self._build_query_filters()
            logger.info(f"Built query filters: {json.dumps(query)}")

            # Composite aggregation
            sources = [
                {
                    "date": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "1d",
                            "format": "yyyy-MM-dd"
                        }
                    }
                },
                {"devid": {"terms": {"field": "parsed_fields.devid.keyword"}}},
                {"srcip": {"terms": {"field": "parsed_fields.srcip.keyword"}}},
                {"dstip": {"terms": {"field": "parsed_fields.dstip.keyword"}}},
                {"dstport": {"terms": {"field": "parsed_fields.dstport.keyword"}}},
                {"srcintf": {"terms": {"field": "parsed_fields.srcintf.keyword"}}},
                {"dstintf": {"terms": {"field": "parsed_fields.dstintf.keyword"}}},
                {"proto": {"terms": {"field": "parsed_fields.proto.keyword"}}},
                {"service": {"terms": {"field": "parsed_fields.service.keyword"}}},
                {"action": {"terms": {"field": "parsed_fields.action.keyword"}}},
                {"appcat": {"terms": {"field": "parsed_fields.appcat.keyword"}}}
            ]

            composite_agg = {
                "group_by_fields": {
                    "composite": {
                        "sources": sources,
                        "size": self.paginate_by
                    },
                    "aggs": {
                        "sum_sentbyte": {"sum": {"field": "parsed_fields.sentbyte.value"}},
                        "avg_sentbyte": {"avg": {"field": "parsed_fields.sentbyte.value"}},
                        "sum_rcvdbyte": {"sum": {"field": "parsed_fields.rcvdbyte.value"}},
                        "avg_rcvdbyte": {"avg": {"field": "parsed_fields.rcvdbyte.value"}},
                        "sum_sentpkt": {"sum": {"field": "parsed_fields.sentpkt.value"}},
                        "avg_sentpkt": {"avg": {"field": "parsed_fields.sentpkt.value"}},
                        "sum_rcvdpkt": {"sum": {"field": "parsed_fields.rcvdpkt.value"}},
                        "avg_rcvdpkt": {"avg": {"field": "parsed_fields.rcvdpkt.value"}},
                        "sum_duration": {"sum": {"field": "parsed_fields.duration.value"}},
                        "avg_duration": {"avg": {"field": "parsed_fields.duration.value"}},
                        "session_count": {"cardinality": {"field": "parsed_fields.sessionid.keyword"}}
                    }
                }
            }

            # Get all results up to the current page
            all_buckets = []
            after_key = None
            
            # Fetch pages until we have enough results
            for _ in range(page):
                if after_key:
                    composite_agg["group_by_fields"]["composite"]["after"] = after_key

                response = self.es.search(
                    index=settings.ELASTICSEARCH_INDEX,
                    body={
                        "query": query,
                        "aggs": composite_agg,
                        "size": 0
                    }
                )

                agg_data = response['aggregations']['group_by_fields']
                buckets = agg_data.get('buckets', [])
                
                if not buckets:
                    # No more results
                    break

                all_buckets.extend(buckets)
                after_key = agg_data.get('after_key')
                
                if not after_key:
                    # No more pages
                    break

            # Get the current page's worth of buckets
            start_idx = (page - 1) * self.paginate_by
            end_idx = start_idx + self.paginate_by
            page_buckets = all_buckets[start_idx:end_idx] if start_idx < len(all_buckets) else []

            if not page_buckets and page > 1:
                # If no results and not on first page, return to first page
                self.request.GET = self.request.GET.copy()
                self.request.GET['page'] = '1'
                return self.get_queryset()

            # Store after_key for next page
            self.after_key = after_key if len(page_buckets) == self.paginate_by else None

            return [self._format_bucket(b) for b in page_buckets]

        except Exception as e:
            logger.error(f"Aggregation error: {str(e)}", exc_info=True)
            return []

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        try:
            # Get total count
            count_response = self.es.count(
                index=settings.ELASTICSEARCH_INDEX,
                body={"query": self._build_query_filters()}
            )
            total_count = count_response.get('count', 0)
            
            # Get current page number
            page = self.request.GET.get('page', '1')
            try:
                page = int(page)
                if page < 1:
                    page = 1
            except (TypeError, ValueError):
                page = 1

            # Calculate total pages
            total_pages = (total_count + self.paginate_by - 1) // self.paginate_by
            if total_pages < 1:
                total_pages = 1

            # Ensure page doesn't exceed total pages
            if page > total_pages:
                page = total_pages

            # Calculate page range (show 5 pages around current page)
            start_page = max(1, page - 2)
            end_page = min(total_pages, page + 2)

            context.update({
                'total_count': total_count,
                'page': page,
                'total_pages': total_pages,
                'has_previous': page > 1,
                'has_next': page < total_pages,
                'previous_page': page - 1 if page > 1 else None,
                'next_page': page + 1 if page < total_pages else None,
                'page_range': range(start_page, end_page + 1),
                'show_first': start_page > 1,
                'show_last': end_page < total_pages,
            })

        except Exception as e:
            logger.error(f"Error getting pagination context: {str(e)}")
            context.update({
                'total_count': 0,
                'page': 1,
                'total_pages': 1,
                'has_previous': False,
                'has_next': False,
                'page_range': range(1, 2),
            })
        
        return context

    def _build_query_filters(self):
        query = {"bool": {"must": [], "filter": []}}
        return query

    def _format_bucket(self, bucket):
        key = bucket['key']
        return {
            'date': key.get('date', 'N/A'),
            'devid': key.get('devid', 'N/A'),
            'srcip': key.get('srcip', 'N/A'),
            'dstip': key.get('dstip', 'N/A'),
            'dstport': key.get('dstport', 'N/A'),
            'srcintf': key.get('srcintf', 'N/A'),
            'dstintf': key.get('dstintf', 'N/A'),
            'proto': key.get('proto', 'N/A'),
            'service': key.get('service', 'N/A'),
            'action': key.get('action', 'N/A'),
            'appcat': key.get('appcat', 'N/A'),
            'sum_sentbyte': bucket['sum_sentbyte']['value'],
            'avg_sentbyte': bucket['avg_sentbyte']['value'],
            'sum_rcvdbyte': bucket['sum_rcvdbyte']['value'],
            'avg_rcvdbyte': bucket['avg_rcvdbyte']['value'],
            'sum_sentpkt': bucket['sum_sentpkt']['value'],
            'avg_sentpkt': bucket['avg_sentpkt']['value'],
            'sum_rcvdpkt': bucket['sum_rcvdpkt']['value'],
            'avg_rcvdpkt': bucket['avg_rcvdpkt']['value'],
            'sum_duration': bucket['sum_duration']['value'],
            'avg_duration': bucket['avg_duration']['value'],
            'session_count': bucket['session_count']['value']
        }