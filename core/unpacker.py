# core/unpacker.py
import os
import subprocess
from config import Config

class Unpacker:
    @staticmethod
    def unpack(file_path: str) -> str:
        # Try Unipacker
        unpacked = file_path + '.unpacked'
        try:
            subprocess.run([Config.UNPACKER_PATH, '-o', unpacked, file_path], 
                           check=True, timeout=30)
            if os.path.exists(unpacked) and os.path.getsize(unpacked) > 0:
                return unpacked
        except:
            pass
        # Fallback: Qiling (simplified)
        try:
            from qiling import Qiling
            from qiling.const import QL_VERBOSE
            ql = Qiling([file_path], verbose=QL_VERBOSE.OFF)
            ql.run()
            dump_path = file_path + '.qiling'
            if os.path.exists(dump_path):
                return dump_path
        except:
            pass
        return file_path