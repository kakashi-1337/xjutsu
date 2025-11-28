"""
XJutsu v5 - Admin Configuration
"""

from django.contrib import admin
from .models import Capture, Payload, CollectedPage, WebhookConfig, APIKey


@admin.register(Capture)
class CaptureAdmin(admin.ModelAdmin):
    list_display = ['short_id', 'domain', 'ip_address', 'status', 'fired_at']
    list_filter = ['status', 'fired_at']
    search_fields = ['uri', 'ip_address', 'bot_id']
    readonly_fields = ['id', 'bot_id', 'fired_at', 'created_at']
    ordering = ['-fired_at']


@admin.register(Payload)
class PayloadAdmin(admin.ModelAdmin):
    list_display = ['name', 'user', 'short_id', 'is_active', 'fire_count', 'created_at']
    list_filter = ['is_active', 'user']
    search_fields = ['name', 'description']


@admin.register(CollectedPage)
class CollectedPageAdmin(admin.ModelAdmin):
    list_display = ['uri', 'capture', 'created_at']
    search_fields = ['uri']


@admin.register(WebhookConfig)
class WebhookConfigAdmin(admin.ModelAdmin):
    list_display = ['name', 'user', 'webhook_type', 'is_active']
    list_filter = ['webhook_type', 'is_active']


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ['name', 'user', 'key', 'is_active', 'last_used']
    list_filter = ['is_active']
    readonly_fields = ['key']
