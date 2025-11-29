"""
XJutsu v5 - Parameter Extractor
by Dave Lester B. Mondina / ANBU Black Ops Security

Extract and analyze potential XSS injection points.
"""

import re
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from enum import Enum

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class InjectionContext(Enum):
    """Context where injection point appears"""
    HTML_TEXT = "html_text"           # Between tags: <div>HERE</div>
    HTML_ATTRIBUTE = "html_attr"       # In attribute: <div title="HERE">
    HTML_ATTRIBUTE_UNQUOTED = "html_attr_unquoted"  # <div title=HERE>
    HTML_HREF = "html_href"            # In href/src: <a href="HERE">
    HTML_EVENT = "html_event"          # In event: <div onclick="HERE">
    JS_STRING = "js_string"            # In JS string: var x = "HERE"
    JS_CODE = "js_code"                # In JS code: eval(HERE)
    CSS_VALUE = "css_value"            # In CSS: style="color: HERE"
    URL_PARAM = "url_param"            # In URL param
    COMMENT = "comment"                # In comment: <!-- HERE -->
    UNKNOWN = "unknown"


@dataclass
class InjectionPoint:
    """Represents a potential XSS injection point"""
    url: str
    param: str
    method: str
    context: InjectionContext
    reflects: bool = False
    reflection_count: int = 0
    vulnerable_chars: List[str] = None
    form_data: Dict = None
    notes: str = ""

    def __post_init__(self):
        if self.vulnerable_chars is None:
            self.vulnerable_chars = []


class ParameterExtractor:
    """
    Extract and analyze parameters for XSS vulnerabilities.

    Features:
    - Reflection detection
    - Context detection (HTML, JS, attribute, etc.)
    - Special character filtering analysis
    - JS sink detection
    """

    # Test payload for reflection detection (unique, unlikely to appear naturally)
    REFLECTION_PROBE = "xjutsu7e3m9k2"

    # Characters to test for filtering
    XSS_CHARS = ['<', '>', '"', "'", '/', '\\', '`', '(', ')', '{', '}', '[', ']', ';', '=']

    # JS sinks that can lead to XSS
    JS_SINKS = [
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'\.write\s*\(',
        r'\.writeln\s*\(',
        r'eval\s*\(',
        r'setTimeout\s*\(',
        r'setInterval\s*\(',
        r'new\s+Function\s*\(',
        r'\.replace\s*\([^,]+,\s*[^)]*\$',
        r'location\s*=',
        r'location\.href\s*=',
        r'location\.assign\s*\(',
        r'location\.replace\s*\(',
        r'document\.domain\s*=',
        r'\$\s*\(',  # jQuery
        r'\.html\s*\(',  # jQuery .html()
        r'\.append\s*\(',  # jQuery .append()
        r'\.prepend\s*\(',
        r'\.after\s*\(',
        r'\.before\s*\(',
        r'\.replaceWith\s*\(',
        r'v-html\s*=',  # Vue
        r'dangerouslySetInnerHTML',  # React
        r'\[innerHTML\]',  # Angular
        r'bypassSecurityTrust',  # Angular
    ]

    def __init__(
        self,
        timeout: int = 10,
        headers: Dict = None,
        cookies: Dict = None,
        verify_ssl: bool = False,
    ):
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

        # Compile JS sink patterns
        self.sink_patterns = [re.compile(p, re.IGNORECASE) for p in self.JS_SINKS]

    def _make_request(self, url: str, method: str = 'GET', data: Dict = None) -> Optional[requests.Response]:
        """Make HTTP request"""
        try:
            if method.upper() == 'GET':
                return self.session.get(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                )
            else:
                return self.session.post(
                    url,
                    data=data,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                )
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None

    def _inject_param(self, url: str, param: str, value: str, method: str = 'GET', form_data: Dict = None) -> str:
        """Inject value into parameter and return modified URL or form data"""
        if method.upper() == 'GET':
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [value]
            new_query = urlencode(params, doseq=True)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        else:
            # For POST, modify form_data
            if form_data is None:
                form_data = {}
            form_data[param] = value
            return url

    def check_reflection(self, url: str, param: str, method: str = 'GET', form_data: Dict = None) -> Tuple[bool, int, str]:
        """
        Check if parameter value is reflected in response.

        Returns:
            Tuple of (reflects: bool, count: int, response_html: str)
        """
        probe = self.REFLECTION_PROBE

        if method.upper() == 'GET':
            test_url = self._inject_param(url, param, probe, 'GET')
            response = self._make_request(test_url, 'GET')
        else:
            test_data = (form_data or {}).copy()
            test_data[param] = probe
            response = self._make_request(url, 'POST', test_data)

        if response is None:
            return False, 0, ""

        html = response.text
        count = html.count(probe)

        return count > 0, count, html

    def detect_context(self, html: str, probe: str) -> InjectionContext:
        """Detect the context where the probe appears"""
        # Find position of probe
        pos = html.find(probe)
        if pos == -1:
            return InjectionContext.UNKNOWN

        # Get surrounding context (500 chars before and after)
        start = max(0, pos - 500)
        end = min(len(html), pos + len(probe) + 500)
        context = html[start:end]

        # Check for JS context
        if re.search(r'<script[^>]*>.*?' + re.escape(probe), context, re.DOTALL | re.IGNORECASE):
            # Check if in string
            before_probe = context[:context.find(probe)]
            if re.search(r'["\'][^"\']*$', before_probe):
                return InjectionContext.JS_STRING
            return InjectionContext.JS_CODE

        # Check for event handler
        if re.search(r'on\w+\s*=\s*["\'][^"\']*' + re.escape(probe), context, re.IGNORECASE):
            return InjectionContext.HTML_EVENT

        # Check for href/src attribute
        if re.search(r'(?:href|src|action)\s*=\s*["\'][^"\']*' + re.escape(probe), context, re.IGNORECASE):
            return InjectionContext.HTML_HREF

        # Check for attribute (quoted)
        if re.search(r'\w+\s*=\s*["\'][^"\']*' + re.escape(probe) + r'[^"\']*["\']', context, re.IGNORECASE):
            return InjectionContext.HTML_ATTRIBUTE

        # Check for attribute (unquoted)
        if re.search(r'\w+\s*=\s*[^\s>]*' + re.escape(probe), context, re.IGNORECASE):
            return InjectionContext.HTML_ATTRIBUTE_UNQUOTED

        # Check for CSS
        if re.search(r'style\s*=\s*["\'][^"\']*' + re.escape(probe), context, re.IGNORECASE):
            return InjectionContext.CSS_VALUE

        # Check for comment
        if re.search(r'<!--[^>]*' + re.escape(probe), context):
            return InjectionContext.COMMENT

        # Default to HTML text
        return InjectionContext.HTML_TEXT

    def check_char_filtering(self, url: str, param: str, method: str = 'GET', form_data: Dict = None) -> List[str]:
        """Check which XSS-relevant characters are not filtered"""
        unfiltered = []

        for char in self.XSS_CHARS:
            probe = f"{self.REFLECTION_PROBE}{char}{self.REFLECTION_PROBE}"

            if method.upper() == 'GET':
                test_url = self._inject_param(url, param, probe, 'GET')
                response = self._make_request(test_url, 'GET')
            else:
                test_data = (form_data or {}).copy()
                test_data[param] = probe
                response = self._make_request(url, 'POST', test_data)

            if response and probe in response.text:
                unfiltered.append(char)

        return unfiltered

    def detect_js_sinks(self, html: str) -> List[Dict]:
        """Detect potential JS sinks in HTML/JavaScript"""
        sinks = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            for script in soup.find_all('script'):
                if script.string:
                    js_code = script.string
                    for i, pattern in enumerate(self.sink_patterns):
                        matches = pattern.finditer(js_code)
                        for match in matches:
                            sinks.append({
                                'sink': self.JS_SINKS[i],
                                'match': match.group(),
                                'position': match.start(),
                                'context': js_code[max(0, match.start()-50):match.end()+50],
                            })

            # Also check inline event handlers
            for tag in soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if attr.startswith('on') and value:
                        for i, pattern in enumerate(self.sink_patterns):
                            if pattern.search(str(value)):
                                sinks.append({
                                    'sink': self.JS_SINKS[i],
                                    'match': str(value)[:100],
                                    'position': 0,
                                    'context': f'{tag.name} {attr}="{value}"',
                                })

        except Exception as e:
            logger.error(f"Error detecting sinks: {e}")

        return sinks

    def analyze_injection_point(
        self,
        url: str,
        param: str,
        method: str = 'GET',
        form_data: Dict = None,
        deep_analysis: bool = True,
    ) -> InjectionPoint:
        """
        Analyze a potential injection point.

        Args:
            url: Target URL
            param: Parameter name
            method: HTTP method
            form_data: Form data for POST requests
            deep_analysis: Perform character filtering analysis

        Returns:
            InjectionPoint with analysis results
        """
        # Check reflection
        reflects, count, html = self.check_reflection(url, param, method, form_data)

        injection_point = InjectionPoint(
            url=url,
            param=param,
            method=method,
            context=InjectionContext.UNKNOWN,
            reflects=reflects,
            reflection_count=count,
            form_data=form_data,
        )

        if reflects:
            # Detect context
            injection_point.context = self.detect_context(html, self.REFLECTION_PROBE)

            # Deep analysis
            if deep_analysis:
                injection_point.vulnerable_chars = self.check_char_filtering(url, param, method, form_data)

                # Add notes based on analysis
                notes = []
                if '<' in injection_point.vulnerable_chars and '>' in injection_point.vulnerable_chars:
                    notes.append("HTML tags allowed")
                if '"' in injection_point.vulnerable_chars or "'" in injection_point.vulnerable_chars:
                    notes.append("Quotes allowed")
                if '(' in injection_point.vulnerable_chars and ')' in injection_point.vulnerable_chars:
                    notes.append("Parentheses allowed")

                injection_point.notes = "; ".join(notes)

        return injection_point

    def analyze_multiple(self, injection_points: List[Dict], deep_analysis: bool = False) -> List[InjectionPoint]:
        """Analyze multiple injection points"""
        results = []

        for point in injection_points:
            result = self.analyze_injection_point(
                url=point['url'],
                param=point['param'],
                method=point.get('method', 'GET'),
                form_data=point.get('form_data'),
                deep_analysis=deep_analysis,
            )
            results.append(result)

        return results
