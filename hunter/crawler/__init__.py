"""
XJutsu v5 - XSS Crawler Module
by Dave Lester B. Mondina / ANBU Black Ops Security

Automated XSS discovery and verification through callback detection.
"""

from .spider import XSSSpider
from .extractor import ParameterExtractor
from .injector import PayloadInjector
from .scanner import XSSScanner

__all__ = ['XSSSpider', 'ParameterExtractor', 'PayloadInjector', 'XSSScanner']
