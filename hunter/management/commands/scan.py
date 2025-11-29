"""
XJutsu v5 - XSS Scan Command
by Dave Lester B. Mondina / ANBU Black Ops Security

Usage:
    python manage.py scan https://example.com
    python manage.py scan https://example.com --depth 5 --max-urls 200
    python manage.py scan https://example.com --xjutsu-domain 6u.gg --no-inject
"""

import sys
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from hunter.models import ScanTarget, ScanInjectionPoint
from hunter.crawler import XSSScanner, ScanConfig


class Command(BaseCommand):
    help = 'Run XSS scan on a target URL'

    def add_arguments(self, parser):
        parser.add_argument('target', type=str, help='Target URL to scan')

        # Spider settings
        parser.add_argument(
            '--depth', '-d',
            type=int,
            default=3,
            help='Maximum crawl depth (default: 3)'
        )
        parser.add_argument(
            '--max-urls', '-m',
            type=int,
            default=100,
            help='Maximum URLs to crawl (default: 100)'
        )
        parser.add_argument(
            '--delay',
            type=float,
            default=0.5,
            help='Delay between requests in seconds (default: 0.5)'
        )

        # XJutsu settings
        parser.add_argument(
            '--xjutsu-domain', '-x',
            type=str,
            default='6u.gg',
            help='Your XJutsu domain (default: 6u.gg)'
        )

        # Injection settings
        parser.add_argument(
            '--no-inject',
            action='store_true',
            help='Skip payload injection (recon only)'
        )
        parser.add_argument(
            '--max-payloads',
            type=int,
            default=3,
            help='Max payloads per injection point (default: 3)'
        )

        # Analysis settings
        parser.add_argument(
            '--no-deep-analysis',
            action='store_true',
            help='Skip deep analysis (char filtering)'
        )

        # Output settings
        parser.add_argument(
            '--output-dir', '-o',
            type=str,
            default='scans',
            help='Output directory for scan results (default: scans)'
        )
        parser.add_argument(
            '--quiet', '-q',
            action='store_true',
            help='Minimal output'
        )

        # Request settings
        parser.add_argument(
            '--cookie', '-c',
            type=str,
            action='append',
            help='Cookie in format name=value (can be used multiple times)'
        )
        parser.add_argument(
            '--header', '-H',
            type=str,
            action='append',
            help='Header in format Name: Value (can be used multiple times)'
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=10,
            help='Request timeout in seconds (default: 10)'
        )

    def handle(self, *args, **options):
        target = options['target']

        # Validate URL
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target

        # Parse cookies
        cookies = {}
        if options['cookie']:
            for c in options['cookie']:
                if '=' in c:
                    name, value = c.split('=', 1)
                    cookies[name.strip()] = value.strip()

        # Parse headers
        headers = {}
        if options['header']:
            for h in options['header']:
                if ':' in h:
                    name, value = h.split(':', 1)
                    headers[name.strip()] = value.strip()

        # Create scan config
        config = ScanConfig(
            target=target,
            xjutsu_domain=options['xjutsu_domain'],
            max_depth=options['depth'],
            max_urls=options['max_urls'],
            crawl_delay=options['delay'],
            deep_analysis=not options['no_deep_analysis'],
            inject_payloads=not options['no_inject'],
            max_payloads_per_point=options['max_payloads'],
            timeout=options['timeout'],
            headers=headers,
            cookies=cookies,
            output_dir=options['output_dir'],
        )

        # Create DB record
        scan_target = ScanTarget.objects.create(
            target_url=target,
            max_depth=config.max_depth,
            max_urls=config.max_urls,
            xjutsu_domain=config.xjutsu_domain,
            status='pending',
        )

        quiet = options['quiet']

        def progress_callback(stage, message, data=None):
            if not quiet:
                if stage == 'DONE':
                    self.stdout.write(self.style.SUCCESS(f'[{stage}] {message}'))
                else:
                    self.stdout.write(f'[{stage}] {message}')

        # Banner
        if not quiet:
            self.stdout.write(self.style.HTTP_INFO('''
╔═══════════════════════════════════════════════════════════╗
║     XJutsu v5 - XSS Scanner                               ║
║     by Dave Lester B. Mondina / ANBU Black Ops Security   ║
╚═══════════════════════════════════════════════════════════╝
'''))
            self.stdout.write(f'Target: {target}')
            self.stdout.write(f'XJutsu Domain: {config.xjutsu_domain}')
            self.stdout.write(f'Max Depth: {config.max_depth}')
            self.stdout.write(f'Max URLs: {config.max_urls}')
            self.stdout.write('')

        try:
            # Update status
            scan_target.status = 'crawling'
            scan_target.started_at = timezone.now()
            scan_target.save()

            # Create scanner
            scanner = XSSScanner(
                target=target,
                xjutsu_domain=config.xjutsu_domain,
                config=config,
                progress_callback=progress_callback,
            )

            # Run scan
            result = scanner.scan()

            # Update DB with results
            scan_target.status = 'completed'
            scan_target.completed_at = timezone.now()
            scan_target.urls_crawled = result.urls_crawled
            scan_target.injection_points_found = result.injection_points_found
            scan_target.reflecting_params = result.reflecting_params
            scan_target.payloads_injected = result.payloads_injected
            scan_target.save()

            # Save injection points to DB
            for ip in result.injection_points:
                ScanInjectionPoint.objects.create(
                    scan=scan_target,
                    url=ip.url,
                    param=ip.param,
                    method=ip.method,
                    context=ip.context.value,
                    reflects=ip.reflects,
                    reflection_count=ip.reflection_count,
                    vulnerable_chars=','.join(ip.vulnerable_chars) if ip.vulnerable_chars else '',
                )

            # Save injection results with tracking IDs
            for ir in result.injection_results:
                if ir.success:
                    try:
                        sip = ScanInjectionPoint.objects.get(
                            scan=scan_target,
                            url=ir.injection_point.url,
                            param=ir.injection_point.param,
                        )
                        sip.tracking_id = ir.tracking_id
                        sip.payload_injected = ir.payload
                        sip.injected_at = ir.timestamp
                        sip.save()
                    except ScanInjectionPoint.DoesNotExist:
                        pass

            # Print summary
            if not quiet:
                self.stdout.write('')
                self.stdout.write(self.style.SUCCESS('═' * 60))
                self.stdout.write(self.style.SUCCESS('SCAN COMPLETE'))
                self.stdout.write(self.style.SUCCESS('═' * 60))
                self.stdout.write(f'URLs Crawled: {result.urls_crawled}')
                self.stdout.write(f'Injection Points: {result.injection_points_found}')
                self.stdout.write(f'Reflecting Params: {result.reflecting_params}')
                self.stdout.write(f'Payloads Injected: {result.payloads_injected}')
                self.stdout.write('')

                # List reflecting parameters
                reflecting = [ip for ip in result.injection_points if ip.reflects]
                if reflecting:
                    self.stdout.write(self.style.WARNING('Reflecting Parameters:'))
                    for ip in reflecting[:20]:  # Show first 20
                        chars = ','.join(ip.vulnerable_chars[:5]) if ip.vulnerable_chars else 'none'
                        self.stdout.write(f'  [{ip.method}] {ip.param} @ {ip.url[:60]}')
                        self.stdout.write(f'       Context: {ip.context.value}, Unfiltered: {chars}')

                self.stdout.write('')
                self.stdout.write(self.style.HTTP_INFO(f'Waiting for callbacks on {config.xjutsu_domain}...'))
                self.stdout.write(self.style.HTTP_INFO('Check your XJutsu dashboard for verified XSS!'))
                self.stdout.write('')

        except KeyboardInterrupt:
            scan_target.status = 'error'
            scan_target.error_message = 'Cancelled by user'
            scan_target.completed_at = timezone.now()
            scan_target.save()
            self.stdout.write(self.style.WARNING('\nScan cancelled.'))
            sys.exit(1)

        except Exception as e:
            scan_target.status = 'error'
            scan_target.error_message = str(e)
            scan_target.completed_at = timezone.now()
            scan_target.save()
            raise CommandError(f'Scan failed: {e}')
