"""
XJutsu v5 - GeoIP Service
IP to Location lookup using free APIs
"""

import logging
import requests
from functools import lru_cache

logger = logging.getLogger(__name__)


class GeoIPService:
    """
    Lookup geographic location from IP address
    Uses free APIs - no API key required
    """
    
    # Free GeoIP APIs (fallback chain)
    APIS = [
        {
            'name': 'ip-api.com',
            'url': 'http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org',
            'parser': lambda r: {
                'country': r.get('country', ''),
                'country_code': r.get('countryCode', ''),
                'city': r.get('city', ''),
                'lat': r.get('lat'),
                'lon': r.get('lon'),
                'isp': r.get('isp', ''),
                'org': r.get('org', ''),
            } if r.get('status') == 'success' else None
        },
        {
            'name': 'ipapi.co',
            'url': 'https://ipapi.co/{ip}/json/',
            'parser': lambda r: {
                'country': r.get('country_name', ''),
                'country_code': r.get('country_code', ''),
                'city': r.get('city', ''),
                'lat': r.get('latitude'),
                'lon': r.get('longitude'),
                'isp': r.get('org', ''),
                'org': r.get('org', ''),
            } if not r.get('error') else None
        },
        {
            'name': 'ipwho.is',
            'url': 'https://ipwho.is/{ip}',
            'parser': lambda r: {
                'country': r.get('country', ''),
                'country_code': r.get('country_code', ''),
                'city': r.get('city', ''),
                'lat': r.get('latitude'),
                'lon': r.get('longitude'),
                'isp': r.get('connection', {}).get('isp', ''),
                'org': r.get('connection', {}).get('org', ''),
            } if r.get('success') else None
        },
    ]
    
    @classmethod
    @lru_cache(maxsize=1000)
    def lookup(cls, ip_address):
        """
        Lookup IP address location
        Returns dict with country, city, lat, lon, etc.
        Results are cached to avoid API rate limits
        """
        if not ip_address or ip_address in ['127.0.0.1', 'localhost', '::1']:
            return {
                'country': 'Localhost',
                'country_code': 'XX',
                'city': 'Local',
                'lat': None,
                'lon': None,
                'isp': '',
                'org': '',
            }
        
        for api in cls.APIS:
            try:
                url = api['url'].format(ip=ip_address)
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    result = api['parser'](data)
                    
                    if result:
                        logger.info(f"GeoIP lookup success via {api['name']}: {ip_address} -> {result['country']}, {result['city']}")
                        return result
                        
            except requests.Timeout:
                logger.warning(f"GeoIP timeout for {api['name']}")
                continue
            except Exception as e:
                logger.warning(f"GeoIP error for {api['name']}: {e}")
                continue
        
        # All APIs failed
        logger.error(f"All GeoIP APIs failed for {ip_address}")
        return {
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'lat': None,
            'lon': None,
            'isp': '',
            'org': '',
        }
    
    @classmethod
    def get_flag_emoji(cls, country_code):
        """
        Convert country code to flag emoji
        """
        if not country_code or len(country_code) != 2:
            return '🌍'
        
        # Convert to regional indicator symbols
        return ''.join(chr(ord(c) + 127397) for c in country_code.upper())
    
    @classmethod
    def format_location(cls, geo_data):
        """
        Format location string with flag
        """
        if not geo_data:
            return '🌍 Unknown'
        
        flag = cls.get_flag_emoji(geo_data.get('country_code', ''))
        city = geo_data.get('city', 'Unknown')
        country = geo_data.get('country', 'Unknown')
        
        if city and city != 'Unknown':
            return f"{flag} {city}, {country}"
        return f"{flag} {country}"
    
    @classmethod
    def enrich_capture(cls, capture):
        """
        Enrich capture object with GeoIP data
        """
        if capture.ip_address:
            geo = cls.lookup(capture.ip_address)
            
            capture.country = geo.get('country', '')
            capture.city = geo.get('city', '')
            
            if geo.get('lat') and geo.get('lon'):
                capture.geolocation = f"{geo['lat']},{geo['lon']}"
            
            capture.save(update_fields=['country', 'city', 'geolocation'])
            
        return capture
