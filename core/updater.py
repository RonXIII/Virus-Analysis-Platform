# core/updater.py
import os
import subprocess
from datetime import datetime, timedelta

class RuleUpdater:
    def __init__(self, rule_dir: str = "./rules/yara"):
        self.rule_dir = rule_dir
        self.last_update = None
        self.sources = [
            {'name': 'signature-base', 'repo': 'https://github.com/Neo23x0/signature-base.git'},
            {'name': 'yara-rules', 'repo': 'https://github.com/Yara-Rules/rules.git'}
        ]

    def needs_update(self) -> bool:
        return self.last_update is None or (datetime.now() - self.last_update) > timedelta(hours=24)

    def update_all(self):
        for source in self.sources:
            target = os.path.join(self.rule_dir, source['name'])
            os.makedirs(target, exist_ok=True)
            if os.path.exists(os.path.join(target, '.git')):
                subprocess.run(['git', '-C', target, 'pull'], check=False)
            else:
                subprocess.run(['git', 'clone', source['repo'], target], check=False)
        self.last_update = datetime.now()
        print(f"Rules updated at {self.last_update}")