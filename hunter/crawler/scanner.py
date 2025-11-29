"""
XJutsu v5 - XSS Scanner
by Dave Lester B. Mondina / ANBU Black Ops Security

Main scanner orchestrator - combines spider, extractor, and injector.
"""

import json
import logging
import time
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from .spider import XSSSpider, CrawlResult
from .extractor import ParameterExtractor, InjectionPoint, InjectionContext
from .injector import PayloadInjector, InjectionResult

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Scanner configuration"""
    target: str
    xjutsu_domain: str = "6u.gg"

    # Spider settings
    max_depth: int = 3
    max_urls: int = 100
    crawl_delay: float = 0.5

    # Extractor settings
    deep_analysis: bool = True

    # Injector settings
    inject_payloads: bool = True
    max_payloads_per_point: int = 3
    injection_delay: float = 0.5

    # Request settings
    timeout: int = 10
    headers: Dict = field(default_factory=dict)
    cookies: Dict = field(default_factory=dict)
    verify_ssl: bool = False

    # Output settings
    output_dir: str = "scans"
    save_html: bool = False


@dataclass
class ScanResult:
    """Complete scan result"""
    config: ScanConfig
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"

    # Results
    urls_crawled: int = 0
    injection_points_found: int = 0
    reflecting_params: int = 0
    payloads_injected: int = 0

    # Detailed results
    crawl_results: List[CrawlResult] = field(default_factory=list)
    injection_points: List[InjectionPoint] = field(default_factory=list)
    injection_results: List[InjectionResult] = field(default_factory=list)

    # Pending verifications (tracking_id -> injection info)
    pending_verifications: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'target': self.config.target,
            'xjutsu_domain': self.config.xjutsu_domain,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'status': self.status,
            'stats': {
                'urls_crawled': self.urls_crawled,
                'injection_points_found': self.injection_points_found,
                'reflecting_params': self.reflecting_params,
                'payloads_injected': self.payloads_injected,
            },
            'injection_points': [
                {
                    'url': ip.url,
                    'param': ip.param,
                    'method': ip.method,
                    'context': ip.context.value,
                    'reflects': ip.reflects,
                    'vulnerable_chars': ip.vulnerable_chars,
                }
                for ip in self.injection_points
            ],
            'pending_verifications': {
                tid: {
                    'url': ir.injection_point.url,
                    'param': ir.injection_point.param,
                    'payload_type': ir.payload_type.value,
                    'payload': ir.payload,
                    'injected_url': ir.injected_url,
                    'timestamp': ir.timestamp.isoformat(),
                }
                for tid, ir in self.pending_verifications.items()
            },
        }


class XSSScanner:
    """
    Main XSS Scanner - orchestrates the full scanning process.

    Usage:
        scanner = XSSScanner(
            target="https://example.com",
            xjutsu_domain="6u.gg"
        )
        result = scanner.scan()

        # Results auto-saved to scans/ directory
        # When XSS fires, callback hits your XJutsu server
        # Dashboard shows verified XSS with tracking ID
    """

    def __init__(
        self,
        target: str,
        xjutsu_domain: str = "6u.gg",
        config: ScanConfig = None,
        progress_callback: Callable = None,
    ):
        """
        Initialize the scanner.

        Args:
            target: Target URL to scan
            xjutsu_domain: Your XJutsu domain
            config: Optional ScanConfig object
            progress_callback: Callback for progress updates
        """
        self.target = target
        self.xjutsu_domain = xjutsu_domain
        self.config = config or ScanConfig(target=target, xjutsu_domain=xjutsu_domain)
        self.progress_callback = progress_callback

        # Initialize components
        self.spider = None
        self.extractor = None
        self.injector = None

        # Results
        self.result = None

    def _log_progress(self, stage: str, message: str, data: Dict = None):
        """Log progress and call callback if set"""
        logger.info(f"[{stage}] {message}")
        if self.progress_callback:
            self.progress_callback(stage, message, data)

    def _init_components(self):
        """Initialize scanner components"""
        self.spider = XSSSpider(
            target=self.target,
            max_depth=self.config.max_depth,
            max_urls=self.config.max_urls,
            delay=self.config.crawl_delay,
            timeout=self.config.timeout,
            headers=self.config.headers,
            cookies=self.config.cookies,
        )

        self.extractor = ParameterExtractor(
            timeout=self.config.timeout,
            headers=self.config.headers,
            cookies=self.config.cookies,
            verify_ssl=self.config.verify_ssl,
        )

        self.injector = PayloadInjector(
            xjutsu_domain=self.xjutsu_domain,
            timeout=self.config.timeout,
            delay=self.config.injection_delay,
            headers=self.config.headers,
            cookies=self.config.cookies,
            verify_ssl=self.config.verify_ssl,
        )

    def scan(self) -> ScanResult:
        """
        Run the full scan.

        Returns:
            ScanResult with all findings
        """
        self.result = ScanResult(
            config=self.config,
            start_time=datetime.now(),
        )

        try:
            self._init_components()

            # Phase 1: Crawl
            self._log_progress("CRAWL", f"Starting crawl of {self.target}")
            crawl_results = self.spider.crawl()
            self.result.crawl_results = crawl_results
            self.result.urls_crawled = len(crawl_results)
            self._log_progress("CRAWL", f"Crawled {len(crawl_results)} URLs")

            # Phase 2: Extract injection points
            self._log_progress("EXTRACT", "Extracting injection points")
            raw_points = self.spider.get_injection_points()
            self.result.injection_points_found = len(raw_points)
            self._log_progress("EXTRACT", f"Found {len(raw_points)} potential injection points")

            # Phase 3: Analyze reflection and context
            self._log_progress("ANALYZE", "Analyzing injection points")
            analyzed_points = []
            for i, point in enumerate(raw_points):
                self._log_progress("ANALYZE", f"Analyzing {i+1}/{len(raw_points)}: {point['param']}")
                analyzed = self.extractor.analyze_injection_point(
                    url=point['url'],
                    param=point['param'],
                    method=point.get('method', 'GET'),
                    deep_analysis=self.config.deep_analysis,
                )
                analyzed_points.append(analyzed)

            self.result.injection_points = analyzed_points
            reflecting = [p for p in analyzed_points if p.reflects]
            self.result.reflecting_params = len(reflecting)
            self._log_progress("ANALYZE", f"Found {len(reflecting)} reflecting parameters")

            # Phase 4: Inject payloads
            if self.config.inject_payloads and reflecting:
                self._log_progress("INJECT", f"Injecting payloads into {len(reflecting)} points")
                injection_results = self.injector.inject_multiple(
                    reflecting,
                    max_payloads_per_point=self.config.max_payloads_per_point,
                )
                self.result.injection_results = injection_results
                self.result.payloads_injected = len([r for r in injection_results if r.success])
                self.result.pending_verifications = self.injector.get_pending_verifications()
                self._log_progress("INJECT", f"Injected {self.result.payloads_injected} payloads")

            # Complete
            self.result.status = "completed"
            self.result.end_time = datetime.now()

            # Save results
            self._save_results()

            self._log_progress("DONE", "Scan complete!", self.result.to_dict())

        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.result.status = "error"
            self.result.end_time = datetime.now()
            raise

        return self.result

    def _save_results(self):
        """Save scan results to file"""
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = self.target.replace("https://", "").replace("http://", "").replace("/", "_")
        filename = f"scan_{domain}_{timestamp}.json"

        output_path = output_dir / filename

        with open(output_path, 'w') as f:
            json.dump(self.result.to_dict(), f, indent=2, default=str)

        logger.info(f"Results saved to {output_path}")

    def get_summary(self) -> Dict:
        """Get scan summary"""
        if not self.result:
            return {"status": "not started"}

        return {
            "target": self.target,
            "status": self.result.status,
            "urls_crawled": self.result.urls_crawled,
            "injection_points": self.result.injection_points_found,
            "reflecting_params": self.result.reflecting_params,
            "payloads_injected": self.result.payloads_injected,
            "pending_verifications": len(self.result.pending_verifications),
            "duration": str(self.result.end_time - self.result.start_time) if self.result.end_time else "running",
        }


def quick_scan(target: str, xjutsu_domain: str = "6u.gg") -> ScanResult:
    """
    Quick scan function for simple usage.

    Usage:
        from hunter.crawler import quick_scan
        result = quick_scan("https://example.com", "6u.gg")
    """
    scanner = XSSScanner(target=target, xjutsu_domain=xjutsu_domain)
    return scanner.scan()
