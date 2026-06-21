# core/anti_evasion.py
import os
import ctypes
from typing import Dict

class AntiEvasionDetector:
    @staticmethod
    def check_debugger() -> Dict:
        findings = {}
        try:
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            if kernel32.IsDebuggerPresent():
                findings['IsDebuggerPresent'] = True
            is_debug = ctypes.wintypes.BOOL()
            kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(is_debug))
            if is_debug.value:
                findings['CheckRemoteDebuggerPresent'] = True
        except:
            pass
        try:
            import psutil
            debuggers = ['ollydbg.exe', 'x64dbg.exe', 'windbg.exe', 'ida.exe']
            running = [p.name().lower() for p in psutil.process_iter(['name'])]
            findings['debugger_processes'] = [p for p in debuggers if p in running]
        except:
            pass
        return findings

    @staticmethod
    def check_vm() -> Dict:
        findings = {}
        try:
            import psutil
            vm_procs = ['vmtoolsd.exe', 'vboxservice.exe']
            running = [p.name().lower() for p in psutil.process_iter(['name'])]
            findings['vm_processes'] = [p for p in vm_procs if p in running]
        except:
            pass
        try:
            import wmi
            c = wmi.WMI()
            for sys in c.Win32_ComputerSystem():
                if 'VMware' in sys.Model or 'VirtualBox' in sys.Model:
                    findings['vm_model'] = sys.Model
        except:
            pass
        return findings

    @staticmethod
    def analyze(file_path: str) -> Dict:
        result = {
            'debugger': AntiEvasionDetector.check_debugger(),
            'vm': AntiEvasionDetector.check_vm(),
            'risk_score': 0
        }
        score = 0
        if result['debugger'].get('IsDebuggerPresent'): score += 20
        if result['debugger'].get('debugger_processes'): score += 15
        if result['vm'].get('vm_processes'): score += 10
        if result['vm'].get('vm_model'): score += 15
        result['risk_score'] = min(score, 100)
        return result