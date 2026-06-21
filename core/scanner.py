# core/scanner.py
import os
from datetime import datetime
from core.yara_engine import YARAEngine
from core.ml_detector import MLDetector
from core.anti_evasion import AntiEvasionDetector
from core.sandbox_client import SandboxClient
from core.emulator import Emulator
from core.unpacker import Unpacker
from core.ioc_extractor import IOCExtractor
from core.threat_intel import ThreatIntel
from core.memory_forensics import MemoryAnalyzer
from core.rule_generator import generate_rules
from core.reporting import generate_pdf_report   # <-- Report function imported
from core.updater import RuleUpdater
from config import Config

try:
    from core.deep_ml import DeepMalwareDetector
except ImportError:
    DeepMalwareDetector = None

class VirusScanner:
    def __init__(self, config=None):
        self.config = config or Config()
        self.yara = YARAEngine(rule_dirs=[self.config.RULES_DIR])
        self.ml = MLDetector(model_path=os.path.join(self.config.MODELS_DIR, 'malware_model.pkl'))
        self.deep = DeepMalwareDetector() if DeepMalwareDetector else None
        self.sandbox = SandboxClient(api_url=self.config.SANDBOX_URL,
                                     api_token=self.config.SANDBOX_TOKEN)
        self.emulator = Emulator()
        self.unpacker = Unpacker()
        self.evasion = AntiEvasionDetector()
        self.intel = ThreatIntel()
        self.memory = MemoryAnalyzer()
        self.updater = RuleUpdater()
        self.log_callback = None

    def log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        else:
            print(msg)

    def full_scan(self, file_path: str) -> dict:
        # Step 0: Unpack
        unpacked_path = self.unpacker.unpack(file_path)
        if unpacked_path != file_path:
            file_to_scan = unpacked_path
        else:
            file_to_scan = file_path

        result = {
            'file': os.path.basename(file_path),
            'unpacked': file_to_scan != file_path,
            'timestamp': str(datetime.utcnow()),
            'verdict': 'unknown',
            'score': 0,
            'findings': [],
            'iocs': [],
            'threat_intel': {},
            'report_path': None   # Will be filled later
        }

        # 1. YARA
        try:
            yara_matches = self.yara.scan_file(file_to_scan)
            if yara_matches:
                result['findings'].append({'source': 'yara', 'matches': yara_matches})
                result['score'] += 30
        except Exception as e:
            self.log(f"⚠️ YARA error: {e}")

        # 2. Anti-evasion
        evasion_result = self.evasion.analyze(file_to_scan)
        if evasion_result['risk_score'] > 30:
            result['findings'].append({'source': 'anti_evasion', 'details': evasion_result})
            result['score'] += evasion_result['risk_score'] * 0.3

        # 3. ML (Random Forest)
        try:
            pred, proba = self.ml.predict(file_to_scan)
            self.log(f"ML RF: {pred}, proba: {proba:.4f}")
            if pred == 1:
                result['findings'].append({'source': 'ml_rf', 'probability': proba})
                result['score'] += proba * 20
        except Exception as e:
            self.log(f"⚠️ ML RF failed: {e}")

        # 4. Deep Learning (CNN) if available
        if self.deep:
            try:
                pred, proba = self.deep.predict(file_to_scan)
                self.log(f"ML CNN: {pred}, proba: {proba:.4f}")
                if pred == 1:
                    result['findings'].append({'source': 'ml_cnn', 'probability': proba})
                    result['score'] += proba * 25
            except Exception as e:
                self.log(f"⚠️ ML CNN failed: {e}")

        # 5. Sandbox (dynamic)
        if self.config.SANDBOX_URL:
            sandbox_result = self.sandbox.analyze(file_to_scan)
            if sandbox_result and 'error' not in sandbox_result:
                result['findings'].append({'source': 'sandbox', 'behavior': sandbox_result})
                result['score'] += 30
                iocs = IOCExtractor.extract_iocs(sandbox_result)
                if iocs:
                    result['iocs'].append(iocs)

        # 6. Threat intelligence enrichment (hash)
        with open(file_to_scan, 'rb') as f:
            import hashlib
            sha256 = hashlib.sha256(f.read()).hexdigest()
        vt_data = self.intel.vt_lookup(sha256)
        if vt_data:
            result['threat_intel']['virustotal'] = vt_data

        # Final verdict
        if result['score'] >= 70:
            result['verdict'] = 'malicious'
        elif result['score'] >= 40:
            result['verdict'] = 'suspicious'
        else:
            result['verdict'] = 'benign'

        # 7. Generate PDF report (ENABLED)
        try:
            report_path = generate_pdf_report(result)
            result['report_path'] = report_path
            self.log(f"📄 Report saved to: {report_path}")
        except Exception as e:
            self.log(f"⚠️ Report generation failed: {e}")

        return result

    def update(self):
        self.updater.update_all()
        self.yara.reload_if_changed()