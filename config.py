# config.py
import os
import sys

def get_resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///analysis.db')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret')
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_BACKEND', 'redis://localhost:6379/0')
    
    # Sandbox integration (optional – set to '' if not used)
    SANDBOX_URL = os.getenv('SANDBOX_URL', 'http://localhost:8090')
    SANDBOX_TOKEN = os.getenv('SANDBOX_TOKEN', None)
    
    # Threat intelligence APIs (optional – leave empty if not used)
    VIRUSTOTAL_API_KEY = os.getenv('VT_API_KEY', '')
    OTX_API_KEY = os.getenv('OTX_API_KEY', '')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    
    # Storage paths (auto-detected)
    STORAGE_DIR = get_resource_path('storage')
    RULES_DIR = get_resource_path('rules/yara')
    MODELS_DIR = get_resource_path('models')
    REPORTS_DIR = get_resource_path('reports')
    MONITOR_FOLDER = get_resource_path('drop_folder')
    
    # QEMU / Unpacker (optional – set to '' if not used)
    QEMU_IMAGE = os.getenv('QEMU_IMAGE', '')
    UNPACKER_PATH = os.getenv('UNPACKER_PATH', 'unipacker')