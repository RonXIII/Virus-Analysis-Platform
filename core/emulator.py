# core/emulator.py
import os
import subprocess
import time
import shutil
import tempfile
from datetime import datetime
from config import Config

class Emulator:
    def __init__(self):
        self.image = Config.QEMU_IMAGE
        self.ssh_user = os.getenv('QEMU_SSH_USER', 'user')
        self.ssh_password = os.getenv('QEMU_SSH_PASSWORD', 'password')
        self.qemu_binary = os.getenv('QEMU_BINARY', 'qemu-system-x86_64')

    def run(self, file_path: str, timeout=120) -> dict:
        """Run the file in QEMU and return behavioral logs."""
        if not os.path.exists(self.image):
            return {'error': f'QEMU image not found: {self.image}'}

        # Create a temporary shared folder
        temp_dir = tempfile.mkdtemp(prefix='qemu_share_')
        shutil.copy(file_path, temp_dir)
        file_name = os.path.basename(file_path)

        # QEMU command with shared folder and port forwarding
        qemu_cmd = [
            self.qemu_binary,
            '-m', '2048',
            '-drive', f'file={self.image},format=qcow2',
            '-netdev', 'user,id=net0,hostfwd=tcp::10022-:22',
            '-device', 'e1000,netdev=net0',
            '-virtfs', f'local,path={temp_dir},mount_tag=host_share,security_model=passthrough',
            '-nographic',
            '-display', 'none'
        ]

        # Launch QEMU in background
        print(f"🔄 Starting QEMU with image: {self.image}")
        proc = subprocess.Popen(qemu_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Wait for VM to boot and SSH to become available
        time.sleep(30)

        # Copy file into VM and execute it via SSH (using sshpass or keys)
        # For demonstration, we assume SSH is set up with password-less login
        try:
            ssh_cmd = [
                'ssh', '-o', 'StrictHostKeyChecking=no',
                '-p', '10022', f'{self.ssh_user}@localhost',
                f'cp /host_share/{file_name} /tmp/ && cd /tmp && chmod +x {file_name} && timeout {timeout} ./{file_name}'
            ]
            result = subprocess.run(ssh_cmd, capture_output=True, timeout=timeout+10)
            output = result.stdout.decode('utf-8', errors='ignore')
            stderr = result.stderr.decode('utf-8', errors='ignore')
        except subprocess.TimeoutExpired:
            output = "[TIMEOUT] Execution exceeded time limit"
            stderr = ""
        except Exception as e:
            output = f"[ERROR] {str(e)}"
            stderr = ""

        # Terminate QEMU
        proc.terminate()
        proc.wait(timeout=5)

        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)

        # Parse output for indicators
        behavior = {
            'timestamp': str(datetime.utcnow()),
            'executed': file_name,
            'stdout': output[:1000],  # limit to avoid huge logs
            'stderr': stderr[:500],
            'suspicious_indicators': []
        }

        # Simple heuristics: look for network patterns, error codes, etc.
        if 'http://' in output.lower() or 'https://' in output.lower():
            behavior['suspicious_indicators'].append('Network connection detected')
        if 'administrator' in output.lower() or 'system32' in output.lower():
            behavior['suspicious_indicators'].append('Privilege escalation attempt')
        if 'reg' in output.lower() or 'hklm' in output.lower():
            behavior['suspicious_indicators'].append('Registry modification')
        if 'persistence' in output.lower() or 'startup' in output.lower():
            behavior['suspicious_indicators'].append('Persistence mechanism')

        return behavior