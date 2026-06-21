# core/ioc_extractor.py
import re
from stix2 import Indicator, Bundle
from datetime import datetime

class IOCExtractor:
    @staticmethod
    def extract_iocs(analysis_result):
        iocs = []
        text = str(analysis_result)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+\b'
        url_pattern = r'https?://[^\s]+'
        hash_pattern = r'[a-fA-F0-9]{32,64}'

        for ip in re.findall(ip_pattern, text):
            iocs.append(Indicator(pattern=f"[ipv4-addr:value = '{ip}']", created=datetime.now()))
        for domain in re.findall(domain_pattern, text):
            if '.' in domain and not domain.startswith('http'):
                iocs.append(Indicator(pattern=f"[domain-name:value = '{domain}']"))
        for url in re.findall(url_pattern, text):
            iocs.append(Indicator(pattern=f"[url:value = '{url}']"))
        for h in re.findall(hash_pattern, text):
            if len(h) == 64:
                iocs.append(Indicator(pattern=f"[file:hashes.SHA-256 = '{h}']"))
        return Bundle(objects=iocs).serialize() if iocs else None