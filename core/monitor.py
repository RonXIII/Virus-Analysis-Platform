# core/monitor.py
import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.scanner import VirusScanner
from config import Config

class MonitorHandler(FileSystemEventHandler):
    def __init__(self, callback=None):
        self.callback = callback or self.default_callback
        self.scanner = VirusScanner()

    def default_callback(self, result):
        print(f"[MONITOR] Result: {result.get('file')} -> {result.get('verdict')}")

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            # Ignore temporary and hidden files
            if os.path.basename(file_path).startswith('.'):
                return
            print(f"[MONITOR] New file detected: {file_path}")
            try:
                result = self.scanner.full_scan(file_path)
                self.callback(result)
            except Exception as e:
                print(f"[MONITOR] Error scanning {file_path}: {e}")

    def on_moved(self, event):
        if not event.is_directory:
            print(f"[MONITOR] File moved to: {event.dest_path}")
            self.on_created(event)  # treat as new file

def start_monitoring(path=None, callback=None):
    """Start monitoring a folder for new files."""
    path = path or Config.MONITOR_FOLDER
    os.makedirs(path, exist_ok=True)

    event_handler = MonitorHandler(callback)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()

    print(f"👀 Monitoring started on: {path}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()