# gui_main.py – Full corrected with logout fix
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from datetime import datetime
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import VirusScanner
from config import Config
from profile_manager import (
    create_profile,
    login as auth_login,
    get_api_keys,
    save_api_key,
    DB_PATH
)

# =====================================================================
# LOGIN WINDOW
# =====================================================================
class LoginWindow:
    def __init__(self, root, on_success):
        self.root = root
        self.on_success = on_success
        self.window = tk.Toplevel(root)
        self.window.title("🔐 Login – Virus Analysis Platform")
        self.window.geometry("400x350")
        self.window.configure(bg='#0a0e17')
        self.window.resizable(False, False)
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)

        x = (self.window.winfo_screenwidth() // 2) - 200
        y = (self.window.winfo_screenheight() // 2) - 175
        self.window.geometry(f"400x350+{x}+{y}")

        tk.Label(self.window, text="🛡️ Virus Analysis Platform",
                 font=('Segoe UI', 16, 'bold'), bg='#0a0e17', fg='#4fc3f7').pack(pady=(30, 5))
        tk.Label(self.window, text="Secure Profile Login",
                 font=('Segoe UI', 10), bg='#0a0e17', fg='#8899bb').pack(pady=(0, 20))

        tk.Label(self.window, text="Username (min 4 chars)", bg='#0a0e17', fg='#e8edf5', font=('Segoe UI', 10)).pack(anchor='w', padx=50, pady=(10, 2))
        self.username_entry = tk.Entry(self.window, bg='#1a2438', fg='#e8edf5', insertbackground='white',
                                       font=('Segoe UI', 10), width=30)
        self.username_entry.pack(padx=50, pady=(0, 10), fill='x')
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())

        tk.Label(self.window, text="Password", bg='#0a0e17', fg='#e8edf5', font=('Segoe UI', 10)).pack(anchor='w', padx=50, pady=(5, 2))
        self.password_entry = tk.Entry(self.window, bg='#1a2438', fg='#e8edf5', insertbackground='white',
                                       font=('Segoe UI', 10), width=30, show='*')
        self.password_entry.pack(padx=50, pady=(0, 15), fill='x')
        self.password_entry.bind('<Return>', lambda e: self.do_login())

        btn_frame = tk.Frame(self.window, bg='#0a0e17')
        btn_frame.pack(pady=10)
        self.login_btn = tk.Button(btn_frame, text="Login", command=self.do_login,
                                   bg='#4fc3f7', fg='#0a0e17', font=('Segoe UI', 10, 'bold'),
                                   padx=20, relief='flat', cursor='hand2')
        self.login_btn.pack(side='left', padx=5)
        self.register_btn = tk.Button(btn_frame, text="Create Account", command=self.show_register,
                                      bg='#1a2438', fg='#e8edf5', font=('Segoe UI', 10),
                                      padx=20, relief='flat', cursor='hand2')
        self.register_btn.pack(side='left', padx=5)

        self.status_label = tk.Label(self.window, text="", bg='#0a0e17', fg='#ef5350', font=('Segoe UI', 9))
        self.status_label.pack(pady=5)
        self.username_entry.focus()

    def do_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            self.status_label.config(text="Please enter username and password.", fg='#ffca28')
            return
        profile = auth_login(username, password)
        if profile:
            self.status_label.config(text="✅ Login successful!", fg='#66bb6a')
            self.window.after(500, lambda: self.close(profile))
        else:
            self.status_label.config(text="❌ Invalid username or password.", fg='#ef5350')
            self.password_entry.delete(0, 'end')
            self.password_entry.focus()

    def show_register(self):
        RegisterWindow(self.window, self)

    def close(self, profile):
        self.window.destroy()
        self.on_success(profile)

    def on_close(self):
        self.root.destroy()

class RegisterWindow:
    def __init__(self, parent, login_window):
        self.login_window = login_window
        self.window = tk.Toplevel(parent)
        self.window.title("Create Account")
        self.window.geometry("400x430")
        self.window.configure(bg='#0a0e17')
        self.window.resizable(False, False)

        x = (self.window.winfo_screenwidth() // 2) - 200
        y = (self.window.winfo_screenheight() // 2) - 215
        self.window.geometry(f"400x430+{x}+{y}")

        tk.Label(self.window, text="📝 Create Account",
                 font=('Segoe UI', 16, 'bold'), bg='#0a0e17', fg='#4fc3f7').pack(pady=(30, 5))
        tk.Label(self.window, text="Create a new profile to store your API keys securely.",
                 font=('Segoe UI', 10), bg='#0a0e17', fg='#8899bb').pack(pady=(0, 15))

        tk.Label(self.window, text="Username (min 4 characters)", bg='#0a0e17', fg='#e8edf5', font=('Segoe UI', 10)).pack(anchor='w', padx=50, pady=(10, 2))
        self.username_entry = tk.Entry(self.window, bg='#1a2438', fg='#e8edf5', insertbackground='white',
                                       font=('Segoe UI', 10), width=30)
        self.username_entry.pack(padx=50, pady=(0, 10), fill='x')

        tk.Label(self.window, text="Password (min 8 chars)", bg='#0a0e17', fg='#e8edf5', font=('Segoe UI', 10)).pack(anchor='w', padx=50, pady=(5, 2))
        tk.Label(self.window, text="Must have: uppercase, lowercase, digit, special char", bg='#0a0e17', fg='#8899bb', font=('Segoe UI', 8)).pack(anchor='w', padx=50, pady=(0, 2))
        self.password_entry = tk.Entry(self.window, bg='#1a2438', fg='#e8edf5', insertbackground='white',
                                       font=('Segoe UI', 10), width=30, show='*')
        self.password_entry.pack(padx=50, pady=(0, 10), fill='x')

        tk.Label(self.window, text="Confirm Password", bg='#0a0e17', fg='#e8edf5', font=('Segoe UI', 10)).pack(anchor='w', padx=50, pady=(5, 2))
        self.confirm_entry = tk.Entry(self.window, bg='#1a2438', fg='#e8edf5', insertbackground='white',
                                      font=('Segoe UI', 10), width=30, show='*')
        self.confirm_entry.pack(padx=50, pady=(0, 15), fill='x')

        self.req_label = tk.Label(self.window, text="", bg='#0a0e17', fg='#8899bb', font=('Segoe UI', 8))
        self.req_label.pack(pady=(0, 10))
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)

        btn_frame = tk.Frame(self.window, bg='#0a0e17')
        btn_frame.pack(pady=10)
        self.create_btn = tk.Button(btn_frame, text="Create Account", command=self.do_create,
                                    bg='#4fc3f7', fg='#0a0e17', font=('Segoe UI', 10, 'bold'),
                                    padx=20, relief='flat', cursor='hand2')
        self.create_btn.pack(side='left', padx=5)
        self.cancel_btn = tk.Button(btn_frame, text="Cancel", command=self.window.destroy,
                                    bg='#1a2438', fg='#e8edf5', font=('Segoe UI', 10),
                                    padx=20, relief='flat', cursor='hand2')
        self.cancel_btn.pack(side='left', padx=5)

        self.status_label = tk.Label(self.window, text="", bg='#0a0e17', fg='#ef5350', font=('Segoe UI', 9))
        self.status_label.pack(pady=5)
        self.username_entry.focus()

    def check_password_strength(self, event=None):
        password = self.password_entry.get()
        requirements = []
        requirements.append("✅ 8+ chars" if len(password) >= 8 else "❌ 8+ chars")
        requirements.append("✅ Uppercase" if re.search(r'[A-Z]', password) else "❌ Uppercase")
        requirements.append("✅ Lowercase" if re.search(r'[a-z]', password) else "❌ Lowercase")
        requirements.append("✅ Digit" if re.search(r'[0-9]', password) else "❌ Digit")
        requirements.append("✅ Special" if re.search(r'[!@#$%^&*(),.?":{}|<>]', password) else "❌ Special")
        self.req_label.config(text=" | ".join(requirements), fg='#8899bb')

    def do_create(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not username:
            self.status_label.config(text="Please enter a username.", fg='#ffca28')
            return
        if len(username) < 4:
            self.status_label.config(text="Username must be at least 4 characters.", fg='#ffca28')
            return
        if len(password) < 8:
            self.status_label.config(text="Password must be at least 8 characters.", fg='#ffca28')
            return
        if not re.search(r'[A-Z]', password):
            self.status_label.config(text="Password must contain at least one uppercase letter.", fg='#ffca28')
            return
        if not re.search(r'[a-z]', password):
            self.status_label.config(text="Password must contain at least one lowercase letter.", fg='#ffca28')
            return
        if not re.search(r'[0-9]', password):
            self.status_label.config(text="Password must contain at least one digit.", fg='#ffca28')
            return
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            self.status_label.config(text="Password must contain at least one special character.", fg='#ffca28')
            return

        if password != confirm:
            self.status_label.config(text="Passwords do not match.", fg='#ef5350')
            return

        if create_profile(username, password):
            self.status_label.config(text="✅ Account created! Please login.", fg='#66bb6a')
            self.window.after(1000, self.window.destroy)
        else:
            self.status_label.config(text="❌ Username already exists.", fg='#ef5350')

# =====================================================================
# TOOLTIP CLASS
# =====================================================================
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind('<Enter>', self.enter)
        widget.bind('<Leave>', self.leave)
        widget.bind('<Motion>', self.motion)

    def enter(self, event):
        x, y, _, _ = self.widget.bbox('insert')
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify='left',
                         background='#ffffe0', relief='solid', borderwidth=1,
                         font=('Segoe UI', 9))
        label.pack()

    def leave(self, event):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

    def motion(self, event):
        if self.tip_window:
            x, y, _, _ = self.widget.bbox('insert')
            x += self.widget.winfo_rootx() + 25
            y += self.widget.winfo_rooty() + 20
            self.tip_window.wm_geometry(f"+{x}+{y}")

# =====================================================================
# WORKERS
# =====================================================================
class TrainingWorker(threading.Thread):
    def __init__(self, train_func, log_callback, progress_callback, done_callback):
        super().__init__()
        self.train_func = train_func
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self.done_callback = done_callback

    def run(self):
        try:
            self.log_callback("🚀 Starting training...")
            self.train_func(self.progress_callback)
            self.log_callback("✅ Training completed!")
            self.done_callback()
        except Exception as e:
            import traceback
            self.log_callback(f"❌ Training error: {str(e)}\n{traceback.format_exc()}")
            self.done_callback()

class DownloadWorker(threading.Thread):
    def __init__(self, source, tags, limit, output_dir, api_key, mb_api_key, log_callback, progress_callback, done_callback):
        super().__init__()
        self.source = source
        self.tags = tags
        self.limit = limit
        self.output_dir = output_dir
        self.api_key = api_key
        self.mb_api_key = mb_api_key
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self.done_callback = done_callback

    def run(self):
        try:
            if self.source == "TheZoo (GitHub)":
                from gui_downloaders import TheZooDownloader
                downloader = TheZooDownloader(
                    self.output_dir,
                    log_callback=self.log_callback,
                    progress_callback=self.progress_callback
                )
                downloader.run(self.tags, self.limit)
            elif self.source == "MalShare":
                from gui_downloaders import MalShareDownloader
                downloader = MalShareDownloader(
                    self.output_dir,
                    log_callback=self.log_callback,
                    progress_callback=self.progress_callback,
                    api_key=self.api_key,
                    mb_api_key=self.mb_api_key
                )
                downloader.run(self.tags, self.limit)
            elif self.source == "VirusSign":
                from gui_downloaders import VirusSignDownloader
                downloader = VirusSignDownloader(
                    self.output_dir,
                    log_callback=self.log_callback,
                    progress_callback=self.progress_callback,
                    api_key=self.api_key
                )
                downloader.run(self.tags, self.limit)
            else:
                from gui_downloaders import MalwareBazaarDownloader
                downloader = MalwareBazaarDownloader(
                    self.output_dir,
                    log_callback=self.log_callback,
                    progress_callback=self.progress_callback,
                    api_key=self.api_key
                )
                downloader.run(self.tags, self.limit)
            self.log_callback("✅ Download and extraction complete!")
            self.done_callback()
        except Exception as e:
            import traceback
            self.log_callback(f"❌ Download error: {str(e)}\n{traceback.format_exc()}")
            self.done_callback()

# =====================================================================
# MAIN GUI APPLICATION
# =====================================================================
class MalwareScannerApp:
    def __init__(self, root, profile):
        self.root = root
        self.profile = profile
        self.root.title(f"🛡️ Virus Analysis Platform – {profile['username']}")
        self.root.geometry("1150x1050")
        self.root.configure(bg='#0a0e17')
        self.root.option_add('*tearOff', False)

        self.api_keys = get_api_keys(profile['id'], profile['key'])

        # ---- Style Configuration ----
        style = ttk.Style()
        style.theme_use('clam')
        bg_dark = '#0a0e17'
        bg_card = '#111927'
        bg_input = '#1a2438'
        fg_primary = '#e8edf5'
        fg_secondary = '#8899bb'
        accent = '#4fc3f7'
        success = '#66bb6a'
        danger = '#ef5350'
        warning = '#ffca28'

        style.configure('.', background=bg_dark, foreground=fg_primary)
        style.configure('TNotebook', background=bg_dark, borderwidth=0)
        style.configure('TNotebook.Tab', background='#111927', foreground=fg_secondary,
                        padding=[20, 12], font=('Segoe UI', 10, 'bold'))
        style.map('TNotebook.Tab',
                  background=[('selected', '#1a2438')],
                  foreground=[('selected', accent)])
        style.configure('TLabel', background=bg_dark, foreground=fg_primary, font=('Segoe UI', 10))
        style.configure('TButton', background='#1a2438', foreground=fg_primary, font=('Segoe UI', 10, 'bold'),
                        padding=10, borderwidth=0, relief='flat')
        style.map('TButton',
                  background=[('active', '#2a3a5a'), ('pressed', '#0f1a2a')])
        style.configure('Accent.TButton', background=accent, foreground='#0a0e17',
                        font=('Segoe UI', 10, 'bold'))
        style.map('Accent.TButton',
                  background=[('active', '#81d4fa'), ('pressed', '#0288d1')])
        style.configure('Success.TButton', background=success, foreground='#0a0e17',
                        font=('Segoe UI', 10, 'bold'))
        style.map('Success.TButton',
                  background=[('active', '#81c784'), ('pressed', '#388e3c')])
        style.configure('Danger.TButton', background=danger, foreground='#0a0e17',
                        font=('Segoe UI', 10, 'bold'))
        style.map('Danger.TButton',
                  background=[('active', '#ef5350'), ('pressed', '#c62828')])
        style.configure('TFrame', background=bg_dark)
        style.configure('TEntry', fieldbackground=bg_input, foreground=fg_primary,
                        insertcolor=fg_primary, borderwidth=1, relief='flat')
        style.configure('TSpinbox', fieldbackground=bg_input, foreground=fg_primary)
        style.configure('TLabelframe', background=bg_card, foreground=fg_primary,
                        borderwidth=1, relief='solid')
        style.configure('TLabelframe.Label', background=bg_card, foreground=accent,
                        font=('Segoe UI', 11, 'bold'))
        style.configure('TProgressbar', background=accent, troughcolor='#1a2438',
                        borderwidth=0, lightcolor=accent, darkcolor=accent)

        # ---- Header ----
        header = tk.Frame(root, bg='#0f1a2a', height=60)
        header.pack(fill='x', side='top', pady=(0, 1))
        tk.Label(header, text="🛡️  VAP", font=('Segoe UI', 20, 'bold'),
                 bg='#0f1a2a', fg='#4fc3f7').pack(side='left', padx=25, pady=10)
        tk.Label(header, text=f"Welcome, {profile['username']}", font=('Segoe UI', 11),
                 bg='#0f1a2a', fg='#8899bb').pack(side='left', padx=5, pady=10)

        logout_btn = tk.Button(header, text="🚪 Logout", command=self.logout,
                               bg='#1a2438', fg='#e8edf5', font=('Segoe UI', 9),
                               relief='flat', cursor='hand2')
        logout_btn.pack(side='right', padx=10, pady=10)

        # ---- Main Notebook ----
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=15, pady=10)

        # ---------- Scan Tab ----------
        self.scan_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_tab, text="📊 Scan")

        file_frame = ttk.LabelFrame(self.scan_tab, text="File Selection", padding=15)
        file_frame.pack(pady=10, padx=15, fill='x')
        self.file_path_var = tk.StringVar()
        entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=80)
        entry.pack(side='left', padx=(0,10), fill='x', expand=True)
        browse_btn = ttk.Button(file_frame, text="📂 Browse", command=self.browse_file)
        browse_btn.pack(side='left')
        ToolTip(browse_btn, "Select a file for analysis")

        action_frame = ttk.Frame(self.scan_tab)
        action_frame.pack(pady=12)
        self.scan_btn = ttk.Button(action_frame, text="▶  Analyze", command=self.start_scan,
                                   style='Accent.TButton')
        self.scan_btn.pack(side='left', padx=5)
        ToolTip(self.scan_btn, "Start analysis")
        clear_btn = ttk.Button(action_frame, text="🗑️ Clear Log", command=self.clear_log)
        clear_btn.pack(side='left', padx=5)
        ToolTip(clear_btn, "Clear the log output")

        self.scan_progress = ttk.Progressbar(self.scan_tab, mode='indeterminate', length=400)
        self.scan_progress.pack(pady=5)

        results_frame = ttk.LabelFrame(self.scan_tab, text="Analysis Results", padding=12)
        results_frame.pack(pady=10, padx=15, fill='x')
        self.verdict_label = ttk.Label(results_frame, text="⏳ Waiting...",
                                       font=('Segoe UI', 14, 'bold'), foreground='#8899bb')
        self.verdict_label.pack(side='left', padx=10)
        self.score_label = ttk.Label(results_frame, text="Score: --",
                                     font=('Segoe UI', 12), foreground='#8899bb')
        self.score_label.pack(side='left', padx=20)

        log_frame = ttk.LabelFrame(self.scan_tab, text="Log", padding=10)
        log_frame.pack(pady=10, padx=15, fill='both', expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap='word', font=('Consolas', 9),
                                                  bg='#0a0e17', fg='#b0c4de', insertbackground='white',
                                                  borderwidth=0, highlightthickness=0)
        self.log_text.pack(fill='both', expand=True)

        # ---------- Train Tab ----------
        self.train_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.train_tab, text="🧠 Train")

        ttk.Label(self.train_tab, text="Model Training", font=('Segoe UI', 16, 'bold'),
                  foreground='#4fc3f7').grid(row=0, column=0, columnspan=3, pady=(15,10), padx=20, sticky='w')

        ttk.Label(self.train_tab, text="Malware Samples:").grid(row=1, column=0, sticky='w', padx=25, pady=6)
        self.malware_path_var = tk.StringVar(value=os.path.join(os.getcwd(), "malware_samples", "extracted"))
        ttk.Entry(self.train_tab, textvariable=self.malware_path_var, width=65).grid(row=1, column=1, padx=5, pady=6)
        btn_browse_mal = ttk.Button(self.train_tab, text="Browse", command=lambda: self.browse_folder(self.malware_path_var))
        btn_browse_mal.grid(row=1, column=2, padx=5)

        ttk.Label(self.train_tab, text="Benign Samples:").grid(row=2, column=0, sticky='w', padx=25, pady=6)
        self.benign_path_var = tk.StringVar(value=os.path.join(os.getcwd(), "benign_samples"))
        ttk.Entry(self.train_tab, textvariable=self.benign_path_var, width=65).grid(row=2, column=1, padx=5, pady=6)
        btn_browse_ben = ttk.Button(self.train_tab, text="Browse", command=lambda: self.browse_folder(self.benign_path_var))
        btn_browse_ben.grid(row=2, column=2, padx=5)

        btn_frame = ttk.Frame(self.train_tab)
        btn_frame.grid(row=3, column=0, columnspan=3, pady=15)
        self.train_rf_btn = ttk.Button(btn_frame, text="🔥 Train RF", command=self.start_rf_training)
        self.train_rf_btn.pack(side='left', padx=8)
        self.train_cnn_btn = ttk.Button(btn_frame, text="🧠 Train CNN", command=self.start_cnn_training)
        self.train_cnn_btn.pack(side='left', padx=8)
        self.reload_btn = ttk.Button(btn_frame, text="🔄 Reload", command=self.reload_models)
        self.reload_btn.pack(side='left', padx=8)

        pbar_frame = ttk.Frame(self.train_tab)
        pbar_frame.grid(row=4, column=0, columnspan=3, pady=5)
        self.train_progress_var = tk.IntVar(value=0)
        self.train_progress = ttk.Progressbar(pbar_frame, variable=self.train_progress_var,
                                              maximum=100, length=450)
        self.train_progress.pack(side='left', padx=5)
        self.train_progress_label = ttk.Label(pbar_frame, text="0%", foreground='#4fc3f7')
        self.train_progress_label.pack(side='left', padx=5)
        self.train_status = ttk.Label(self.train_tab, text="Status: Idle", foreground='#8899bb')
        self.train_status.grid(row=5, column=0, columnspan=3, pady=2)

        info_frame = ttk.LabelFrame(self.train_tab, text="Model Status", padding=10)
        info_frame.grid(row=6, column=0, columnspan=3, pady=10, padx=20, sticky='we')
        self.rf_info_label = ttk.Label(info_frame, text="RF: ❌ Not trained", foreground='#b0c4de')
        self.rf_info_label.pack(anchor='w')
        self.cnn_info_label = ttk.Label(info_frame, text="CNN: ❌ Not trained", foreground='#b0c4de')
        self.cnn_info_label.pack(anchor='w')
        self.update_model_info()

        # ---------- Download Tab ----------
        self.download_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.download_tab, text="⬇️ Download")

        ttk.Label(self.download_tab, text="Sample Acquisition", font=('Segoe UI', 16, 'bold'),
                  foreground='#4fc3f7').grid(row=0, column=0, columnspan=4, pady=(15,10), padx=20, sticky='w')

        ttk.Label(self.download_tab, text="Source:").grid(row=1, column=0, sticky='w', padx=25, pady=6)
        self.source_var = tk.StringVar(value="TheZoo (GitHub)")
        source_combo = ttk.Combobox(self.download_tab, textvariable=self.source_var,
                                    values=["TheZoo (GitHub)", "MalwareBazaar", "MalShare", "VirusSign"],
                                    width=20, state="readonly")
        source_combo.grid(row=1, column=1, sticky='w', padx=5, pady=6)
        ToolTip(source_combo, "Select the source for malware samples")
        source_combo.bind('<<ComboboxSelected>>', self.on_source_change)

        self.api_key_label = ttk.Label(self.download_tab, text="API Key:")
        self.api_key_label.grid(row=2, column=0, sticky='w', padx=25, pady=6)
        self.api_key_var = tk.StringVar(value="")
        self.api_key_entry = ttk.Entry(self.download_tab, textvariable=self.api_key_var, width=45)
        self.api_key_entry.grid(row=2, column=1, padx=5, pady=6)
        self.save_key_btn = ttk.Button(self.download_tab, text="💾 Save Key", command=self.save_api_key,
                                       style='Accent.TButton')
        self.save_key_btn.grid(row=2, column=2, padx=5)
        ToolTip(self.save_key_btn, "Save this API key to your profile")
        self.test_btn = ttk.Button(self.download_tab, text="🔑 Test", command=self.test_api_key, style='Accent.TButton')
        self.test_btn.grid(row=2, column=3, padx=5)

        ttk.Label(self.download_tab, text="Output Folder:").grid(row=3, column=0, sticky='w', padx=25, pady=6)
        self.download_path_var = tk.StringVar(value=os.path.join(os.getcwd(), "malware_samples"))
        ttk.Entry(self.download_tab, textvariable=self.download_path_var, width=45).grid(row=3, column=1, padx=5, pady=6)
        btn_browse_dl = ttk.Button(self.download_tab, text="Browse", command=lambda: self.browse_folder(self.download_path_var))
        btn_browse_dl.grid(row=3, column=2, padx=5)

        ttk.Label(self.download_tab, text="Families/Tags:").grid(row=4, column=0, sticky='w', padx=25, pady=6)
        self.families_var = tk.StringVar(value="emotet,zeus,wannacry,petya,mirai,locky,dridex,trickbot,ryuk,conti")
        entry_families = ttk.Entry(self.download_tab, textvariable=self.families_var, width=45)
        entry_families.grid(row=4, column=1, padx=5, pady=6)

        ttk.Label(self.download_tab, text="Per family:").grid(row=5, column=0, sticky='w', padx=25, pady=6)
        self.limit_var = tk.IntVar(value=10)
        ttk.Spinbox(self.download_tab, from_=1, to=100, textvariable=self.limit_var, width=10).grid(row=5, column=1, sticky='w', padx=5, pady=6)

        pbar_dl = ttk.Frame(self.download_tab)
        pbar_dl.grid(row=6, column=0, columnspan=4, pady=10)
        self.download_progress_var = tk.IntVar(value=0)
        self.download_progress = ttk.Progressbar(pbar_dl, variable=self.download_progress_var,
                                                 maximum=100, length=400)
        self.download_progress.pack(side='left', padx=5)
        self.download_progress_label = ttk.Label(pbar_dl, text="0%", foreground='#4fc3f7')
        self.download_progress_label.pack(side='left', padx=5)

        btn_dl_frame = ttk.Frame(self.download_tab)
        btn_dl_frame.grid(row=7, column=0, columnspan=4, pady=10)
        self.download_btn = ttk.Button(btn_dl_frame, text="⬇️  Download", command=self.start_download,
                                       style='Success.TButton')
        self.download_btn.pack(side='left', padx=5)
        self.download_status = ttk.Label(self.download_tab, text="Idle", foreground='#8899bb')
        self.download_status.grid(row=8, column=0, columnspan=4, pady=2)

        # ---- Status Bar ----
        self.status_var = tk.StringVar(value="🟢 Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief='sunken', anchor='w',
                               background='#0f1a2a', foreground='#8899bb', font=('Segoe UI', 9))
        status_bar.pack(side='bottom', fill='x')

        # ---- Initialize Scanner ----
        self.scanner = None
        try:
            self.scanner = VirusScanner()
            self.log("✅ Scanner initialized.")
            self.reload_models()
        except Exception as e:
            self.log(f"⚠️ Init warning: {e}")

        self.current_worker = None
        self.download_progress_var.trace('w', self.update_download_label)
        self.train_progress_var.trace('w', self.update_train_label)
        self.on_source_change()

    # ==================== PROFILE METHODS ====================
    def save_api_key(self):
        source = self.source_var.get()
        api_key = self.api_key_var.get().strip()
        if not api_key:
            messagebox.showerror("Error", "No API key to save.")
            return
        if source == "TheZoo (GitHub)":
            messagebox.showinfo("Info", "TheZoo does not require an API key.")
            return

        service = source.lower().replace(" ", "_")
        if save_api_key(self.profile['id'], service, self.profile['key'], api_key):
            self.api_keys[service] = api_key
            self.log(f"✅ {source} API key saved to profile.")
            messagebox.showinfo("Success", f"API key for {source} saved successfully!")
        else:
            messagebox.showerror("Error", "Failed to save API key.")

    def load_api_key(self):
        source = self.source_var.get()
        service = source.lower().replace(" ", "_")
        if service in self.api_keys:
            self.api_key_var.set(self.api_keys[service])
            self.log(f"🔑 Loaded {source} API key from profile.")
        else:
            self.api_key_var.set("")
            self.log(f"ℹ️ No saved API key for {source}.")

    def on_source_change(self, event=None):
        source = self.source_var.get()
        if source == "TheZoo (GitHub)":
            self.api_key_label.config(text="✅ No API Key Required")
            self.api_key_entry.config(state='disabled')
            self.test_btn.config(state='disabled')
            self.save_key_btn.config(state='disabled')
            self.api_key_var.set("")
        else:
            self.api_key_label.config(text="API Key:")
            self.api_key_entry.config(state='normal')
            self.test_btn.config(state='normal')
            self.save_key_btn.config(state='normal')
            self.load_api_key()

    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            self.root.destroy()
            root = tk.Tk()
            root.withdraw()  # <-- FIX: Hide the empty root window
            login_window = LoginWindow(root, lambda profile: launch_main_app(root, profile))
            root.mainloop()

    # ==================== HELPERS ====================
    def update_download_label(self, *args):
        self.download_progress_label.config(text=f"{self.download_progress_var.get()}%")

    def update_train_label(self, *args):
        self.train_progress_label.config(text=f"{self.train_progress_var.get()}%")

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert('end', f"[{timestamp}] {message}\n")
        self.log_text.see('end')
        self.root.update_idletasks()

    def clear_log(self):
        self.log_text.delete(1.0, 'end')
        self.log("🧹 Log cleared.")

    def browse_file(self):
        path = filedialog.askopenfilename(title="Select file to analyze")
        if path:
            self.file_path_var.set(path)
            self.status_var.set(f"📁 {os.path.basename(path)}")

    def browse_folder(self, path_var):
        folder = filedialog.askdirectory(title="Select folder")
        if folder:
            path_var.set(folder)

    def update_model_info(self):
        rf_path = os.path.join(Config.MODELS_DIR, 'malware_model.pkl')
        cnn_path = os.path.join(Config.MODELS_DIR, 'cnn_model.h5')
        if os.path.exists(rf_path):
            mtime = datetime.fromtimestamp(os.path.getmtime(rf_path)).strftime('%Y-%m-%d %H:%M')
            self.rf_info_label.config(text=f"RF: ✔️  {mtime}")
        else:
            self.rf_info_label.config(text="RF: ❌ Not trained")
        if os.path.exists(cnn_path):
            mtime = datetime.fromtimestamp(os.path.getmtime(cnn_path)).strftime('%Y-%m-%d %H:%M')
            self.cnn_info_label.config(text=f"CNN: ✔️  {mtime}")
        else:
            self.cnn_info_label.config(text="CNN: ❌ Not trained")

    # ==================== SCAN ====================
    def start_scan(self):
        file_path = self.file_path_var.get().strip()
        if not file_path or not os.path.isfile(file_path):
            messagebox.showerror("Error", "Please select a valid file.")
            return
        if self.current_worker and self.current_worker.is_alive():
            messagebox.showwarning("Busy", "A scan is already running.")
            return
        self.verdict_label.config(text="⏳ Analyzing...", foreground='#ffca28')
        self.score_label.config(text="Score: --")
        self.scan_btn.config(state='disabled')
        self.scan_progress.start(10)
        self.status_var.set("🔄 Scanning...")
        self.log_text.delete(1.0, 'end')
        self.log("🚀 Starting scan...")

        class ScanWorker(threading.Thread):
            def __init__(self, scanner, file_path, callback, log_callback):
                super().__init__()
                self.scanner = scanner
                self.file_path = file_path
                self.callback = callback
                self.log_callback = log_callback
            def run(self):
                try:
                    result = self.scanner.full_scan(self.file_path)
                    self.callback(result)
                except Exception as e:
                    import traceback
                    self.log_callback(f"❌ Scan error: {str(e)}\n{traceback.format_exc()}")
                    self.callback(None)
        self.current_worker = ScanWorker(self.scanner, file_path, self.on_scan_complete, self.log)
        self.current_worker.start()

    def on_scan_complete(self, result):
        self.scan_progress.stop()
        self.scan_btn.config(state='normal')
        if result is None:
            self.status_var.set("❌ Scan failed")
            self.verdict_label.config(text="⚠️ Error", foreground='#ef5350')
            return
        verdict = result.get('verdict', 'unknown').upper()
        score = result.get('score', 0)
        color = '#ef5350' if verdict == 'MALICIOUS' else '#ffca28' if verdict == 'SUSPICIOUS' else '#66bb6a'
        icon = '🔴' if verdict == 'MALICIOUS' else '🟡' if verdict == 'SUSPICIOUS' else '🟢'
        self.verdict_label.config(text=f"{icon} {verdict}", foreground=color)
        self.score_label.config(text=f"Score: {score:.1f}")
        self.log("="*50)
        self.log(f"📌 VERDICT: {verdict} (Score: {score:.1f})")
        findings = result.get('findings', [])
        if findings:
            self.log(f"🔎 Findings ({len(findings)} sources):")
            for f in findings:
                source = f.get('source', 'unknown')
                details = str(f)[:150] + ('...' if len(str(f)) > 150 else '')
                self.log(f"   - {source}: {details}")
        else:
            self.log("✅ No suspicious findings.")
        self.log("="*50)
        self.status_var.set(f"✅ Done: {verdict}")

    # ==================== TRAINING ====================
    def start_rf_training(self):
        malware = self.malware_path_var.get().strip()
        benign = self.benign_path_var.get().strip()
        if not os.path.exists(malware) or not os.path.exists(benign):
            messagebox.showerror("Error", "Select valid folders.")
            return
        self.train_status.config(text="Training RF...", foreground='#ffca28')
        self.train_rf_btn.config(state='disabled')
        self.train_progress_var.set(0)

        def train_func(pb):
            from core.ml_detector import MLDetector
            MLDetector().train(malware, benign, progress_callback=pb)

        self.current_worker = TrainingWorker(
            train_func,
            self.log_training_message,
            self.set_train_progress,
            self.training_done
        )
        self.current_worker.start()

    def start_cnn_training(self):
        try:
            import tensorflow as tf
        except ImportError:
            messagebox.showerror("Error", "TensorFlow not installed. Install with: pip install tensorflow")
            return

        malware = self.malware_path_var.get().strip()
        benign = self.benign_path_var.get().strip()
        if not os.path.exists(malware) or not os.path.exists(benign):
            messagebox.showerror("Error", "Select valid folders.")
            return
        self.train_status.config(text="Training CNN...", foreground='#ffca28')
        self.train_cnn_btn.config(state='disabled')
        self.train_progress_var.set(0)

        def train_func(pb):
            from core.deep_ml import DeepMalwareDetector
            DeepMalwareDetector().train(malware, benign, epochs=10, sample_limit=2000,
                                        progress_callback=pb)

        self.current_worker = TrainingWorker(
            train_func,
            self.log_training_message,
            self.set_train_progress,
            self.training_done
        )
        self.current_worker.start()

    def set_train_progress(self, p):
        self.train_progress_var.set(p)

    def log_training_message(self, msg):
        self.log(msg)

    def training_done(self):
        self.train_status.config(text="✔️ Complete", foreground='#66bb6a')
        self.train_rf_btn.config(state='normal')
        self.train_cnn_btn.config(state='normal')
        self.log("🏁 Training finished.")
        self.reload_models()

    def reload_models(self):
        if self.scanner is None:
            self.log("⚠️ Scanner not initialized.")
            return
        try:
            from core.ml_detector import MLDetector
            self.scanner.ml = MLDetector(model_path=os.path.join(self.scanner.config.MODELS_DIR, 'malware_model.pkl'))
            self.log("✅ RF model reloaded.")
        except Exception as e:
            self.log(f"⚠️ RF reload failed: {e}")
        try:
            from core.deep_ml import DeepMalwareDetector
            self.scanner.deep = DeepMalwareDetector(model_path=os.path.join(self.scanner.config.MODELS_DIR, 'cnn_model.h5'))
            self.log("✅ CNN model reloaded.")
        except Exception as e:
            self.log(f"⚠️ CNN reload failed: {e}")
        self.update_model_info()

    # ==================== DOWNLOAD ====================
    def set_download_progress(self, p):
        self.download_progress_var.set(p)

    def test_api_key(self):
        source = self.source_var.get()
        api_key = self.api_key_var.get().strip()
        if source == "TheZoo (GitHub)":
            messagebox.showinfo("Info", "TheZoo does not require an API key.")
            return
        if not api_key:
            messagebox.showerror("Error", "Please enter an API key.")
            return
        output_dir = self.download_path_var.get().strip()
        if not output_dir:
            messagebox.showerror("Error", "Select output folder.")
            return
        self.download_status.config(text="Testing...", foreground='#ffca28')
        self.log(f"🔑 Testing {source} API key...")
        self.download_progress_var.set(0)

        if source == "MalwareBazaar":
            from gui_downloaders import MalwareBazaarDownloader
            downloader = MalwareBazaarDownloader(
                output_dir,
                log_callback=self.log_download_message,
                progress_callback=self.set_download_progress,
                api_key=api_key
            )
            def test_thread():
                success = downloader.test_single_download(tag="redline", limit=1)
                self.root.after(0, lambda: self.download_done_test(success))
            threading.Thread(target=test_thread, daemon=True).start()
        else:
            self.log(f"ℹ️ API key test for {source} not implemented yet.")
            self.download_status.config(text="ℹ️ Manual check required", foreground='#8899bb')

    def download_done_test(self, success):
        if success:
            self.download_status.config(text="✔️ Key valid", foreground='#66bb6a')
            self.log("✅ API key test successful.")
        else:
            self.download_status.config(text="❌ Key invalid", foreground='#ef5350')
            self.log("❌ API key test failed.")
        self.download_progress_var.set(0)

    def start_download(self):
        source = self.source_var.get()
        api_key = self.api_key_var.get().strip() if source != "TheZoo (GitHub)" else None

        if source != "TheZoo (GitHub)" and not api_key:
            messagebox.showerror("Error", f"Please enter your {source} API key.")
            return

        output_dir = self.download_path_var.get().strip()
        families = [f.strip() for f in self.families_var.get().split(',') if f.strip()]
        limit = self.limit_var.get()

        if not output_dir:
            messagebox.showerror("Error", "Please select an output folder.")
            return
        if not families:
            messagebox.showerror("Error", "Please enter at least one malware family/tag.")
            return

        self.download_btn.config(state='disabled')
        self.download_status.config(text="Downloading...", foreground='#ffca28')
        self.log(f"⬇️ Downloading from {source}: {len(families)} families, {limit} each...")
        self.download_progress_var.set(0)

        mb_api_key = self.api_keys.get('malwarebazaar', None)

        self.current_worker = DownloadWorker(
            source=source,
            tags=families,
            limit=limit,
            output_dir=output_dir,
            api_key=api_key,
            mb_api_key=mb_api_key,
            log_callback=self.log_download_message,
            progress_callback=self.set_download_progress,
            done_callback=self.download_done
        )
        self.current_worker.start()

    def log_download_message(self, msg):
        self.log(msg)

    def download_done(self):
        self.download_btn.config(state='normal')
        self.download_status.config(text="✔️ Complete", foreground='#66bb6a')
        self.log("✅ Download complete.")
        self.download_progress_var.set(100)

# =====================================================================
# LAUNCH APP
# =====================================================================
def launch_main_app(root, profile):
    root.deiconify()
    app = MalwareScannerApp(root, profile)
    root.mainloop()

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        from profile_manager import init_database
        init_database()

    root = tk.Tk()
    root.withdraw()
    login_window = LoginWindow(root, lambda profile: launch_main_app(root, profile))
    root.mainloop()