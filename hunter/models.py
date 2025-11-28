"""
XJutsu v5 - Database Models
Stores XSS captures, payloads, and user settings
"""

import uuid
import hashlib
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class Payload(models.Model):
    """
    Stores generated payloads with unique identifiers
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payloads')
    name = models.CharField(max_length=255, help_text="Friendly name for this payload")
    description = models.TextField(blank=True, help_text="Where you're using this payload")
    
    # Payload settings
    collect_cookies = models.BooleanField(default=True)
    collect_localstorage = models.BooleanField(default=True)
    collect_sessionstorage = models.BooleanField(default=True)
    collect_dom = models.BooleanField(default=True)
    collect_screenshot = models.BooleanField(default=True)
    collect_urls = models.BooleanField(default=True)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} ({self.id})"
    
    @property
    def short_id(self):
        return str(self.id)[:8]
    
    @property
    def fire_count(self):
        return self.captures.count()


class Capture(models.Model):
    """
    Stores captured XSS data when a payload fires
    """
    STATUS_CHOICES = [
        ('new', 'New'),
        ('viewed', 'Viewed'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    payload = models.ForeignKey(Payload, on_delete=models.CASCADE, related_name='captures', null=True, blank=True)
    bot_id = models.CharField(max_length=64, db_index=True, help_text="Unique browser session ID")
    
    # Target information
    uri = models.URLField(max_length=2048, help_text="URL where XSS fired")
    origin = models.CharField(max_length=512, blank=True)
    referrer = models.URLField(max_length=2048, blank=True)
    
    # Captured data
    cookies = models.TextField(blank=True)
    localstorage = models.TextField(blank=True)
    sessionstorage = models.TextField(blank=True)
    dom = models.TextField(blank=True, help_text="Captured HTML")
    screenshot = models.TextField(blank=True, help_text="Base64 encoded screenshot")
    page_links = models.TextField(blank=True, help_text="JSON array of page links")
    
    # Client information
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    browser_info = models.TextField(blank=True, help_text="Parsed browser details")
    
    # Geolocation (from IP)
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    geolocation = models.CharField(max_length=100, blank=True)
    
    # Metadata
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    notes = models.TextField(blank=True, help_text="Your notes about this capture")
    
    # Timestamps
    fired_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-fired_at']
        indexes = [
            models.Index(fields=['bot_id']),
            models.Index(fields=['status']),
            models.Index(fields=['fired_at']),
        ]
    
    def __str__(self):
        return f"Capture from {self.uri} at {self.fired_at}"
    
    @property
    def short_id(self):
        return str(self.id)[:8]
    
    @property
    def has_screenshot(self):
        return bool(self.screenshot)
    
    @property
    def domain(self):
        from urllib.parse import urlparse
        try:
            return urlparse(self.uri).netloc
        except:
            return self.uri


class CollectedPage(models.Model):
    """
    Stores pages collected via XHR from the target
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    capture = models.ForeignKey(Capture, on_delete=models.CASCADE, related_name='collected_pages')
    
    uri = models.URLField(max_length=2048)
    html_content = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']


class WebhookConfig(models.Model):
    """
    Stores webhook configurations for notifications
    """
    WEBHOOK_TYPES = [
        ('discord', 'Discord'),
        ('telegram', 'Telegram'),
        ('slack', 'Slack'),
        ('custom', 'Custom URL'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webhooks')
    name = models.CharField(max_length=100)
    webhook_type = models.CharField(max_length=20, choices=WEBHOOK_TYPES)
    webhook_url = models.URLField(max_length=512)
    
    # For Telegram
    telegram_chat_id = models.CharField(max_length=100, blank=True)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} ({self.webhook_type})"


class APIKey(models.Model):
    """
    API keys for programmatic access
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=100)
    key = models.CharField(max_length=64, unique=True, db_index=True)
    
    is_active = models.BooleanField(default=True)
    last_used = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "API Key"
        verbose_name_plural = "API Keys"
    
    def __str__(self):
        return f"{self.name} - {self.key[:8]}..."
    
    @staticmethod
    def generate_key():
        return hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    
    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        super().save(*args, **kwargs)
