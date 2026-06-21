# core/yara_engine.py
import os
import yara
import hashlib
from typing import List, Dict

class YARAEngine:
    def __init__(self, rule_dirs: List[str] = None):
        self.rule_dirs = rule_dirs or ["./rules/yara"]
        self.rules = None
        self.rule_hashes = {}
        self._compile_rules()

    def _compile_rules(self):
        rule_files = {}
        for rule_dir in self.rule_dirs:
            if not os.path.exists(rule_dir):
                continue
            for root, _, files in os.walk(rule_dir):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        path = os.path.join(root, file)
                        rule_files[path] = path
        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
                for path in rule_files.values():
                    self.rule_hashes[path] = self._file_hash(path)
            except yara.SyntaxError as e:
                print(f"YARA compilation error: {e}")

    def _file_hash(self, path: str) -> str:
        with open(path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()

    def reload_if_changed(self) -> bool:
        for rule_dir in self.rule_dirs:
            if not os.path.exists(rule_dir):
                continue
            for root, _, files in os.walk(rule_dir):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        path = os.path.join(root, file)
                        if self.rule_hashes.get(path) != self._file_hash(path):
                            self._compile_rules()
                            return True
        return False

    def scan_file(self, file_path: str) -> List[Dict]:
        if not self.rules or not os.path.exists(file_path):
            return []
        matches = self.rules.match(file_path)
        results = []
        for match in matches:
            results.append({
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': match.tags,
                'meta': match.meta,
                'strings': [(s[0], s[1].decode('utf-8', errors='ignore'))
                            for s in match.strings]
            })
        return results