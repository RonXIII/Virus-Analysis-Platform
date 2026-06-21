# core/sandbox_client.py
import time
import requests
from typing import Dict, Optional

class SandboxClient:
    def __init__(self, api_url: str = "http://localhost:8090", api_token: str = None):
        self.api_url = api_url
        self.session = requests.Session()
        if api_token:
            self.session.headers.update({"Authorization": f"Bearer {api_token}"})

    def submit_file(self, file_path: str) -> Optional[str]:
        try:
            with open(file_path, 'rb') as f:
                resp = self.session.post(f"{self.api_url}/tasks/create/file",
                                         files={'file': f})
            return resp.json().get('task_id') if resp.status_code == 200 else None
        except Exception as e:
            print(f"Sandbox submission failed: {e}")
            return None

    def get_report(self, task_id: str) -> Optional[Dict]:
        try:
            resp = self.session.get(f"{self.api_url}/tasks/report/{task_id}")
            return resp.json() if resp.status_code == 200 else None
        except Exception as e:
            print(f"Report retrieval failed: {e}")
            return None

    def wait_for_report(self, task_id: str, poll_interval: int = 10, max_attempts: int = 30):
        for _ in range(max_attempts):
            report = self.get_report(task_id)
            if report:
                return report
            time.sleep(poll_interval)
        return None

    def analyze(self, file_path: str) -> Dict:
        task_id = self.submit_file(file_path)
        if not task_id:
            return {'error': 'Submission failed'}
        report = self.wait_for_report(task_id)
        if not report:
            return {'error': 'Timeout or analysis failed'}
        behavior = {
            'network': [req.get('uri') for req in report.get('network', {}).get('http', [])],
            'files': [op.get('file_path') for op in report.get('behavior', {}).get('file', [])],
            'registry': [op.get('key') for op in report.get('behavior', {}).get('registry', [])],
            'suspicious': [sig.get('description') for sig in report.get('signatures', [])
                           if sig.get('severity', 0) >= 2]
        }
        return behavior