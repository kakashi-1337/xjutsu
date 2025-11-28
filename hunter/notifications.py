"""
XJutsu v5 - Notification Service
Discord, Telegram, Slack webhook notifications
"""

import json
import logging
import requests
from django.conf import settings
from asgiref.sync import sync_to_async

logger = logging.getLogger(__name__)


class NotificationService:
    """
    Sends notifications to various platforms when XSS fires
    """
    
    @staticmethod
    def format_capture_message(capture):
        """
        Format capture data for notification
        """
        return {
            'title': '🎯 New XSS Capture!',
            'url': capture.uri,
            'domain': capture.domain,
            'ip': capture.ip_address or 'Unknown',
            'country': capture.country or 'Unknown',
            'city': capture.city or 'Unknown',
            'bot_id': capture.bot_id,
            'has_cookies': bool(capture.cookies),
            'has_screenshot': capture.has_screenshot,
            'fired_at': capture.fired_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
        }
    
    @classmethod
    def send_discord(cls, webhook_url, capture):
        """
        Send Discord webhook notification
        """
        try:
            data = cls.format_capture_message(capture)
            
            embed = {
                "title": data['title'],
                "color": 0x8B5CF6,  # Purple
                "fields": [
                    {"name": "🌐 URL", "value": f"```{data['url'][:500]}```", "inline": False},
                    {"name": "🏠 Domain", "value": data['domain'], "inline": True},
                    {"name": "📍 IP", "value": data['ip'], "inline": True},
                    {"name": "🌍 Location", "value": f"{data['city']}, {data['country']}", "inline": True},
                    {"name": "🍪 Cookies", "value": "✅ Yes" if data['has_cookies'] else "❌ No", "inline": True},
                    {"name": "📸 Screenshot", "value": "✅ Yes" if data['has_screenshot'] else "❌ No", "inline": True},
                    {"name": "🤖 Bot ID", "value": f"`{data['bot_id']}`", "inline": True},
                ],
                "footer": {"text": f"XJutsu v5 • {data['fired_at']}"},
                "thumbnail": {"url": "https://i.imgur.com/4M34hi2.png"}  # Crosshair icon
            }
            
            payload = {
                "username": "XJutsu v5",
                "avatar_url": "https://i.imgur.com/4M34hi2.png",
                "embeds": [embed]
            }
            
            response = requests.post(
                webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code in [200, 204]:
                logger.info(f"Discord notification sent for capture {capture.short_id}")
                return True
            else:
                logger.error(f"Discord webhook failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Discord notification error: {e}")
            return False
    
    @classmethod
    def send_telegram(cls, bot_token, chat_id, capture):
        """
        Send Telegram notification
        """
        try:
            data = cls.format_capture_message(capture)
            
            message = f"""
🎯 <b>New XSS Capture!</b>

🌐 <b>URL:</b> <code>{data['url'][:500]}</code>

🏠 <b>Domain:</b> {data['domain']}
📍 <b>IP:</b> {data['ip']}
🌍 <b>Location:</b> {data['city']}, {data['country']}

🍪 <b>Cookies:</b> {'✅' if data['has_cookies'] else '❌'}
📸 <b>Screenshot:</b> {'✅' if data['has_screenshot'] else '❌'}

🤖 <b>Bot ID:</b> <code>{data['bot_id']}</code>

⏰ {data['fired_at']}
            """.strip()
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                logger.info(f"Telegram notification sent for capture {capture.short_id}")
                return True
            else:
                logger.error(f"Telegram API failed: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Telegram notification error: {e}")
            return False
    
    @classmethod
    def send_slack(cls, webhook_url, capture):
        """
        Send Slack webhook notification
        """
        try:
            data = cls.format_capture_message(capture)
            
            payload = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": "🎯 New XSS Capture!", "emoji": True}
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*🌐 URL:*\n`{data['url'][:200]}`"},
                            {"type": "mrkdwn", "text": f"*🏠 Domain:*\n{data['domain']}"},
                            {"type": "mrkdwn", "text": f"*📍 IP:*\n{data['ip']}"},
                            {"type": "mrkdwn", "text": f"*🌍 Location:*\n{data['city']}, {data['country']}"},
                            {"type": "mrkdwn", "text": f"*🍪 Cookies:*\n{'✅' if data['has_cookies'] else '❌'}"},
                            {"type": "mrkdwn", "text": f"*📸 Screenshot:*\n{'✅' if data['has_screenshot'] else '❌'}"},
                        ]
                    },
                    {
                        "type": "context",
                        "elements": [
                            {"type": "mrkdwn", "text": f"XJutsu v5 • Bot: `{data['bot_id']}` • {data['fired_at']}"}
                        ]
                    }
                ]
            }
            
            response = requests.post(
                webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Slack notification sent for capture {capture.short_id}")
                return True
            else:
                logger.error(f"Slack webhook failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Slack notification error: {e}")
            return False
    
    @classmethod
    def send_custom_webhook(cls, webhook_url, capture):
        """
        Send to custom webhook URL (generic JSON)
        """
        try:
            data = cls.format_capture_message(capture)
            data['capture_id'] = str(capture.id)
            
            response = requests.post(
                webhook_url,
                json=data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code in [200, 201, 204]:
                logger.info(f"Custom webhook sent for capture {capture.short_id}")
                return True
            else:
                logger.error(f"Custom webhook failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Custom webhook error: {e}")
            return False
    
    @classmethod
    async def send_all_notifications(cls, capture):
        """
        Send notifications to all configured webhooks for the capture's user
        """
        from hunter.models import WebhookConfig
        
        # Get webhooks - if capture has a payload with user, use that user's webhooks
        # Otherwise, send to all active webhooks
        webhooks = await sync_to_async(list)(
            WebhookConfig.objects.filter(is_active=True)
        )
        
        for webhook in webhooks:
            try:
                if webhook.webhook_type == 'discord':
                    await sync_to_async(cls.send_discord)(webhook.webhook_url, capture)
                elif webhook.webhook_type == 'telegram':
                    await sync_to_async(cls.send_telegram)(
                        webhook.webhook_url,  # Bot token stored here
                        webhook.telegram_chat_id,
                        capture
                    )
                elif webhook.webhook_type == 'slack':
                    await sync_to_async(cls.send_slack)(webhook.webhook_url, capture)
                elif webhook.webhook_type == 'custom':
                    await sync_to_async(cls.send_custom_webhook)(webhook.webhook_url, capture)
            except Exception as e:
                logger.error(f"Failed to send notification via {webhook.name}: {e}")
