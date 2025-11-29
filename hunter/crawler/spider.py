"""
XJutsu v5 - XSS Spider
by Dave Lester B. Mondina / ANBU Black Ops Security

URL discovery and crawling for XSS injection points.
"""

import re
import time
import random
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Set, List, Dict, Optional, Callable
from dataclasses import dataclass, field
from collections import deque

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    """Result of crawling a single URL"""
    url: str
    status_code: int
    content_type: str
    html: str = ""
    links: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    params: List[Dict] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    error: Optional[str] = None


class XSSSpider:
    """
    Web spider for discovering URLs and potential XSS injection points.

    Usage:
        spider = XSSSpider(
            target="https://example.com",
            max_depth=3,
            max_urls=100
        )
        results = spider.crawl()
    """

    # Common file extensions to skip
    SKIP_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
        '.css', '.woff', '.woff2', '.ttf', '.eot',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
        '.exe', '.dll', '.so', '.dmg',
    }

    # User agents for rotation
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    ]

    def __init__(
        self,
        target: str,
        max_depth: int = 3,
        max_urls: int = 100,
        delay: float = 0.5,
        timeout: int = 10,
        headers: Dict = None,
        cookies: Dict = None,
        exclude_patterns: List[str] = None,
        include_subdomains: bool = False,
        respect_robots: bool = True,
        callback: Callable = None,
    ):
        """
        Initialize the spider.

        Args:
            target: Base URL to crawl
            max_depth: Maximum crawl depth
            max_urls: Maximum URLs to crawl
            delay: Delay between requests (seconds)
            timeout: Request timeout (seconds)
            headers: Custom headers
            cookies: Custom cookies
            exclude_patterns: Regex patterns to exclude
            include_subdomains: Crawl subdomains
            respect_robots: Respect robots.txt
            callback: Callback function for each crawled URL
        """
        self.target = target.rstrip('/')
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.delay = delay
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.exclude_patterns = [re.compile(p) for p in (exclude_patterns or [])]
        self.include_subdomains = include_subdomains
        self.respect_robots = respect_robots
        self.callback = callback

        # Parse target URL
        parsed = urlparse(self.target)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme

        # State
        self.visited: Set[str] = set()
        self.queue: deque = deque()
        self.results: List[CrawlResult] = []
        self.session = requests.Session()

        # Stats
        self.stats = {
            'urls_crawled': 0,
            'urls_found': 0,
            'forms_found': 0,
            'params_found': 0,
            'errors': 0,
        }

    def _get_headers(self) -> Dict:
        """Get headers with random user agent"""
        headers = {
            'User-Agent': random.choice(self.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        headers.update(self.headers)
        return headers

    def _is_valid_url(self, url: str) -> bool:
        """Check if URL should be crawled"""
        try:
            parsed = urlparse(url)

            # Must be http/https
            if parsed.scheme not in ('http', 'https'):
                return False

            # Check domain
            if self.include_subdomains:
                if not parsed.netloc.endswith(self.base_domain.split('.')[-2] + '.' + self.base_domain.split('.')[-1]):
                    return False
            else:
                if parsed.netloc != self.base_domain:
                    return False

            # Check extension
            path_lower = parsed.path.lower()
            for ext in self.SKIP_EXTENSIONS:
                if path_lower.endswith(ext):
                    return False

            # Check exclude patterns
            for pattern in self.exclude_patterns:
                if pattern.search(url):
                    return False

            return True

        except Exception:
            return False

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication"""
        parsed = urlparse(url)
        # Remove fragment
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            # Sort query params for consistency
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params = sorted(params.items())
            normalized += '?' + urlencode(sorted_params, doseq=True)
        return normalized

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        links = []
        try:
            soup = BeautifulSoup(html, 'html.parser')

            # <a href>
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urljoin(base_url, href)
                if self._is_valid_url(full_url):
                    links.append(self._normalize_url(full_url))

            # <form action>
            for form in soup.find_all('form', action=True):
                action = form.get('action', '')
                if action:
                    full_url = urljoin(base_url, action)
                    if self._is_valid_url(full_url):
                        links.append(self._normalize_url(full_url))

            # JavaScript URLs (basic extraction)
            for script in soup.find_all('script'):
                if script.string:
                    # Find URLs in JS
                    url_pattern = r'["\']((https?://[^"\']+)|(/[^"\']+))["\']'
                    for match in re.finditer(url_pattern, script.string):
                        url = match.group(1)
                        full_url = urljoin(base_url, url)
                        if self._is_valid_url(full_url):
                            links.append(self._normalize_url(full_url))

        except Exception as e:
            logger.error(f"Error extracting links: {e}")

        return list(set(links))

    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract forms and their inputs"""
        forms = []
        try:
            soup = BeautifulSoup(html, 'html.parser')

            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(base_url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                    'inputs': [],
                }

                # Get all input fields
                for inp in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', ''),
                        'id': inp.get('id', ''),
                        'tag': inp.name,
                    }
                    if input_data['name']:
                        form_data['inputs'].append(input_data)

                if form_data['inputs']:
                    forms.append(form_data)

        except Exception as e:
            logger.error(f"Error extracting forms: {e}")

        return forms

    def _extract_url_params(self, url: str) -> List[Dict]:
        """Extract parameters from URL"""
        params = []
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)

            for name, values in query_params.items():
                params.append({
                    'name': name,
                    'value': values[0] if values else '',
                    'url': url,
                    'method': 'GET',
                })

        except Exception as e:
            logger.error(f"Error extracting URL params: {e}")

        return params

    def _extract_scripts(self, html: str) -> List[str]:
        """Extract inline scripts for sink detection"""
        scripts = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup.find_all('script'):
                if script.string:
                    scripts.append(script.string)
        except Exception:
            pass
        return scripts

    def _crawl_url(self, url: str, depth: int) -> Optional[CrawlResult]:
        """Crawl a single URL"""
        try:
            # Make request
            response = self.session.get(
                url,
                headers=self._get_headers(),
                cookies=self.cookies,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,  # For self-signed certs
            )

            content_type = response.headers.get('Content-Type', '')

            # Only parse HTML
            if 'text/html' not in content_type:
                return CrawlResult(
                    url=url,
                    status_code=response.status_code,
                    content_type=content_type,
                )

            html = response.text

            # Extract data
            links = self._extract_links(html, url)
            forms = self._extract_forms(html, url)
            params = self._extract_url_params(url)
            scripts = self._extract_scripts(html)

            # Update stats
            self.stats['forms_found'] += len(forms)
            self.stats['params_found'] += len(params)
            self.stats['urls_found'] += len(links)

            # Add new links to queue
            for link in links:
                if link not in self.visited and depth + 1 <= self.max_depth:
                    self.queue.append((link, depth + 1))

            return CrawlResult(
                url=url,
                status_code=response.status_code,
                content_type=content_type,
                html=html,
                links=links,
                forms=forms,
                params=params,
                scripts=scripts,
            )

        except requests.exceptions.Timeout:
            self.stats['errors'] += 1
            return CrawlResult(url=url, status_code=0, content_type='', error='Timeout')
        except requests.exceptions.RequestException as e:
            self.stats['errors'] += 1
            return CrawlResult(url=url, status_code=0, content_type='', error=str(e))
        except Exception as e:
            self.stats['errors'] += 1
            return CrawlResult(url=url, status_code=0, content_type='', error=str(e))

    def crawl(self) -> List[CrawlResult]:
        """
        Start crawling from target URL.

        Returns:
            List of CrawlResult objects
        """
        logger.info(f"Starting crawl of {self.target}")

        # Initialize queue with target URL
        self.queue.append((self.target, 0))

        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        while self.queue and len(self.results) < self.max_urls:
            url, depth = self.queue.popleft()

            # Skip if already visited
            normalized = self._normalize_url(url)
            if normalized in self.visited:
                continue

            self.visited.add(normalized)

            # Crawl
            logger.debug(f"Crawling [{depth}] {url}")
            result = self._crawl_url(url, depth)

            if result:
                self.results.append(result)
                self.stats['urls_crawled'] += 1

                # Callback
                if self.callback:
                    self.callback(result)

            # Delay between requests
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, 0.3))

        logger.info(f"Crawl complete. Stats: {self.stats}")
        return self.results

    def get_injection_points(self) -> List[Dict]:
        """
        Get all potential XSS injection points from crawl results.

        Returns:
            List of injection point dictionaries
        """
        injection_points = []

        for result in self.results:
            if result.error:
                continue

            # URL parameters
            for param in result.params:
                injection_points.append({
                    'type': 'url_param',
                    'url': result.url,
                    'param': param['name'],
                    'method': 'GET',
                    'value': param['value'],
                })

            # Form inputs
            for form in result.forms:
                for inp in form['inputs']:
                    # Skip non-injectable types
                    if inp['type'] in ('hidden', 'submit', 'button', 'image', 'file'):
                        # Hidden fields can still be injectable
                        if inp['type'] != 'hidden':
                            continue

                    injection_points.append({
                        'type': 'form_input',
                        'url': form['action'] or result.url,
                        'param': inp['name'],
                        'method': form['method'],
                        'input_type': inp['type'],
                        'form_enctype': form['enctype'],
                    })

        return injection_points
