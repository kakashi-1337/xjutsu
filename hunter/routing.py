"""
XJutsu v5 - WebSocket URL Routing
"""

from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    # XSS Callback endpoint - no auth required
    re_path(r'ws/callback/$', consumers.XSSCallbackConsumer.as_asgi()),
    
    # Dashboard endpoint - requires auth
    re_path(r'ws/dashboard/$', consumers.DashboardConsumer.as_asgi()),
]
