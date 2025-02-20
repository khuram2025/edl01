from django.urls import path
from . import views, agg_views

app_name = 'logs'

urlpatterns = [
    path('', views.SyslogListView.as_view(), name='log_list'),
    path('aggregated-logs/', agg_views.AggregatedLogsListView.as_view(), name='aggregated_logs'),
    path('parsed-list/', views.LogListView.as_view(), name='parsed_list'),
]
