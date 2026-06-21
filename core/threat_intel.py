# core/threat_intel.py
import requests
from config import Config

class ThreatIntel:
    def __init__(self):
        self.vt_key = Config.VIRUSTOTAL_API_KEY
        self.otx_key = Config.OTX_API_KEY

    def vt_lookup(self, file_hash):
        if not self.vt_key:
            return {}
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': self.vt_key}
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            return resp.json().get('data', {})
        except:
            return {}

    def otx_lookup(self, indicator):
        if not self.otx_key:
            return {}
        url = f'https://otx.alienvault.com/api/v1/indicators/{indicator}'
        headers = {'X-OTX-API-KEY': self.otx_key}
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            return resp.json()
        except:
            return {}