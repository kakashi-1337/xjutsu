"""
XJutsu v5 - ASGI Configuration
Handles both HTTP and WebSocket connections
"""

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

# Initialize Django ASGI application early to ensure settings are loaded
django_asgi_app = get_asgi_application()

# Import websocket routes after Django is initialized
from hunter.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    # HTTP requests handled by Django
    "http": django_asgi_app,
    
    # WebSocket connections - No auth required for XSS callbacks
    "websocket": URLRouter(websocket_urlpatterns),
})
