# core/memory_forensics.py
import os
import subprocess
import tempfile
from datetime import datetime

class MemoryAnalyzer:
    def __init__(self, volatility_path='vol'):
        self.volatility_path = volatility_path
        self.plugins = ['pslist', 'malfind', 'netscan', 'cmdscan', 'filescan', 'modules']

    def capture_dump(self, vm_name='win10_vm') -> str:
        """Capture a memory dump from a running VM using vmware-virsh or other tools."""
        # This is OS-specific and requires appropriate tools
        # For VMware: vmware-vim-cmd vmsvc/snapshot.create
        dump_path = tempfile.mktemp(suffix='.mem')
        try:
            # Example: using VirtualBox
            subprocess.run([
                'VBoxManage', 'debugvm', vm_name, 'dumpvmcore', '--filename', dump_path
            ], check=True, timeout=30)
            print(f"✅ Memory dump saved to {dump_path}")
            return dump_path
        except subprocess.TimeoutExpired:
            print("⏱️ Timeout capturing memory dump")
        except Exception as e:
            print(f"❌ Failed to capture memory dump: {e}")
        return None

    def analyze(self, memory_dump_path: str) -> dict:
        """Run Volatility plugins on the memory dump."""
        results = {}
        if not memory_dump_path or not os.path.exists(memory_dump_path):
            return {'error': 'Memory dump not found'}

        # Detect profile (Windows version)
        try:
            profile_cmd = [self.volatility_path, '-f', memory_dump_path, 'imageinfo']
            profile_output = subprocess.check_output(profile_cmd, stderr=subprocess.DEVNULL, timeout=30)
            lines = profile_output.decode('utf-8', errors='ignore')
            # Extract suggested profile (simplified)
            profile = 'Win10x64'
            for line in lines.split('\n'):
                if 'Suggested Profile(s)' in line:
                    profile = line.split(':')[-1].strip().split(',')[0]
                    break
        except:
            profile = 'Win10x64'

        # Run each plugin
        for plugin in self.plugins:
            try:
                cmd = [self.volatility_path, '-f', memory_dump_path, '--profile=' + profile, plugin]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=60)
                results[plugin] = output.decode('utf-8', errors='ignore')
            except subprocess.TimeoutExpired:
                results[plugin] = '[TIMEOUT]'
            except Exception as e:
                results[plugin] = f'[ERROR] {str(e)}'

        results['profile'] = profile
        results['timestamp'] = str(datetime.utcnow())
        return results