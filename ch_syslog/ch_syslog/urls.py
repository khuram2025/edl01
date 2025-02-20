"""
URL configuration for ch_syslog project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from logs.views import SyslogListView, TrafficLogListView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('logs/', include('logs.urls')),
    path('syslogs/', SyslogListView.as_view(), name='syslog_list'),
    path('traffic-logs/', TrafficLogListView.as_view(), name='traffic_logs'),
    path('', SyslogListView.as_view(), name='home'),  # Make it the homepage as well
]
