# core/__init__.py
# This file makes the "core" directory a Python package.

# Import key classes so they can be accessed directly from the package
from .scanner import VirusScanner
from .yara_engine import YARAEngine
from .ml_detector import MLDetector
from .anti_evasion import AntiEvasionDetector
from .sandbox_client import SandboxClient
from .unpacker import Unpacker
from .emulator import Emulator
from .deep_ml import DeepMalwareDetector
from .ioc_extractor import IOCExtractor
from .threat_intel import ThreatIntel
from .memory_forensics import MemoryAnalyzer
from .rule_generator import generate_rules
from .reporting import generate_pdf_report
from .updater import RuleUpdater
from .monitor import start_monitoring
from .model_pipeline import ModelPipeline

# Optionally define what is exported when someone does "from core import *"
__all__ = [
    'VirusScanner',
    'YARAEngine',
    'MLDetector',
    'AntiEvasionDetector',
    'SandboxClient',
    'Unpacker',
    'Emulator',
    'DeepMalwareDetector',
    'IOCExtractor',
    'ThreatIntel',
    'MemoryAnalyzer',
    'generate_rules',
    'generate_pdf_report',
    'RuleUpdater',
    'start_monitoring',
    'ModelPipeline',
]