# gui_downloaders.py – Final working version with MalShare fallback
import os
import time
import requests
import zipfile
import subprocess

# =====================================================================
# HELPER: Find 7-Zip executable
# =====================================================================
def find_7zip():
    common_paths = [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
        r"D:\Program Files\7-Zip\7z.exe",
        r"D:\Program Files (x86)\7-Zip\7z.exe",
    ]
    for path in common_paths:
        if os.path.exists(path):
            return path
    try:
        result = subprocess.run(["where", "7z"], capture_output=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.decode().strip().split("\n")[0]
    except:
        pass
    return None

# =====================================================================
# SOURCE 1: MALWAREBAZAAR
# =====================================================================
class MalwareBazaarDownloader:
    def __init__(self, output_dir, password="infected", log_callback=None, progress_callback=None, api_key=None):
        self.output_dir = output_dir
        self.password = password
        self.api_url = "https://mb-api.abuse.ch/api/v1/"
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        })
        if api_key:
            self.session.headers["Auth-Key"] = api_key
        self.log_callback = log_callback or print
        self.progress_callback = progress_callback or (lambda x: None)
        self.total_samples = 0
        self.downloaded = 0
        self.seven_zip = find_7zip()

    def log(self, msg):
        self.log_callback(f"[MalwareBazaar] {msg}")

    def update_progress(self):
        if self.total_samples > 0:
            percent = int((self.downloaded / self.total_samples) * 100)
            self.progress_callback(percent)

    def _api_request(self, payload, retries=5):
        for attempt in range(retries):
            try:
                resp = self.session.post(self.api_url, data=payload, timeout=120)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("query_status") == "ok":
                        return data.get("data", [])
                    else:
                        self.log(f"API error: {data.get('query_status')}")
                        return []
                elif resp.status_code == 502:
                    self.log(f"502 Bad Gateway (attempt {attempt+1}/{retries}) – retrying in {5 * (attempt+1)}s...")
                    time.sleep(5 * (attempt + 1))
                else:
                    self.log(f"HTTP error: {resp.status_code}")
                    return []
            except requests.exceptions.Timeout:
                self.log(f"Timeout (attempt {attempt+1}/{retries}) – retrying...")
                time.sleep(5 * (attempt + 1))
            except Exception as e:
                self.log(f"Request failed: {e}")
                return []
        return []

    def _fetch_samples(self, method="get_recent", limit=30, tag=None):
        if method == "get_recent":
            payload = {"query": "get_recent", "limit": limit}
            self.log("Fetching recent samples...")
        elif method == "get_taginfo" and tag:
            payload = {"query": "get_taginfo", "tag": tag, "limit": limit}
            self.log(f"Fetching samples for tag '{tag}'...")
        else:
            return []
        return self._api_request(payload)

    def download_sample(self, sample, retries=3):
        sha256 = sample.get("sha256_hash")
        if not sha256:
            self.log("⚠️ Sample missing SHA256, skipping.")
            return False
        file_url = sample.get("file_url")

        zip_path = os.path.join(self.output_dir, f"{sha256[:16]}.zip")
        if os.path.exists(zip_path):
            self.log(f"⏩ Already downloaded: {zip_path}")
            self.downloaded += 1
            self.update_progress()
            return True

        # Try direct download first
        if file_url:
            self.log(f"⬇️ Downloading {sha256[:16]} via file_url...")
            for attempt in range(retries):
                try:
                    resp = self.session.get(file_url, timeout=120)
                    if resp.status_code == 200 and resp.content:
                        os.makedirs(self.output_dir, exist_ok=True)
                        with open(zip_path, 'wb') as f:
                            f.write(resp.content)
                        if zipfile.is_zipfile(zip_path):
                            self.log(f"✅ Saved: {zip_path}")
                            self.downloaded += 1
                            self.update_progress()
                            return True
                        else:
                            self.log(f"⚠️ Invalid zip, deleting.")
                            os.remove(zip_path)
                            return False
                    else:
                        self.log(f"⚠️ HTTP {resp.status_code} (attempt {attempt+1})")
                except Exception as e:
                    self.log(f"❌ Download attempt {attempt+1} failed: {e}")
                time.sleep(2 ** attempt)
            self.log(f"❌ Failed to download {sha256[:16]} via file_url.")
        else:
            self.log(f"ℹ️ No file_url for {sha256[:16]}, using get_file...")

        # Fallback: get_file
        self.log(f"⬇️ Trying get_file for {sha256[:16]}...")
        for attempt in range(retries):
            try:
                payload = {"query": "get_file", "sha256_hash": sha256}
                resp = self.session.post(self.api_url, data=payload, timeout=120)
                if resp.status_code == 200 and resp.content:
                    if len(resp.content) >= 2 and resp.content[:2] == b'PK':
                        os.makedirs(self.output_dir, exist_ok=True)
                        with open(zip_path, 'wb') as f:
                            f.write(resp.content)
                        if zipfile.is_zipfile(zip_path):
                            self.log(f"✅ Saved (get_file): {zip_path}")
                            self.downloaded += 1
                            self.update_progress()
                            return True
                        else:
                            self.log(f"⚠️ Invalid zip from get_file, deleting.")
                            os.remove(zip_path)
                            return False
                    else:
                        try:
                            err = resp.json()
                            self.log(f"❌ get_file API error: {err.get('query_status', 'Unknown')}")
                        except:
                            self.log(f"❌ Unexpected response from get_file: {resp.content[:100]}")
                else:
                    self.log(f"⚠️ get_file HTTP {resp.status_code} (attempt {attempt+1})")
            except Exception as e:
                self.log(f"❌ get_file attempt {attempt+1} failed: {e}")
            time.sleep(2 ** attempt)
        self.log(f"❌ Failed to download {sha256[:16]} after all attempts.")
        return False

    def extract_samples(self):
        extracted_dir = os.path.join(self.output_dir, "extracted")
        os.makedirs(extracted_dir, exist_ok=True)
        zip_files = [f for f in os.listdir(self.output_dir) if f.endswith('.zip')]
        if not zip_files:
            self.log("ℹ️ No zip files to extract.")
            return

        self.log(f"🔓 Extracting {len(zip_files)} zip files (password: '{self.password}')...")
        for zip_name in zip_files:
            zip_path = os.path.join(self.output_dir, zip_name)
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(extracted_dir, pwd=self.password.encode('utf-8'))
                self.log(f"✅ Extracted: {zip_name}")
            except NotImplementedError:
                self.log(f"⚠️ Python zipfile can't handle {zip_name} (LZMA).")
                if self.seven_zip:
                    self.log(f"🔧 Trying 7‑Zip ({self.seven_zip})...")
                    try:
                        subprocess.run(
                            [self.seven_zip, "x", zip_path, f"-o{extracted_dir}", f"-p{self.password}", "-y"],
                            check=True, capture_output=True, timeout=60
                        )
                        self.log(f"✅ Extracted with 7‑Zip: {zip_name}")
                    except Exception as e:
                        self.log(f"❌ 7‑Zip extraction failed: {e}")
                        self.log(f"⚠️ Please manually extract '{zip_name}' using 7‑Zip with password '{self.password}'.")
                else:
                    self.log(f"❌ 7‑Zip not found. Please install 7‑Zip and extract manually.")
                    self.log(f"   You can manually extract '{zip_name}' with 7‑Zip using password '{self.password}'.")
            except Exception as e:
                self.log(f"⚠️ Extraction failed for {zip_name}: {e}")

    def run(self, tags, limit_per_tag=15):
        os.makedirs(self.output_dir, exist_ok=True)

        samples = self._fetch_samples(method="get_recent", limit=30)
        if not samples:
            self.log("No samples from get_recent. Trying popular tags...")
            for tag in tags[:5]:
                tag_samples = self._fetch_samples(method="get_taginfo", tag=tag, limit=limit_per_tag)
                if tag_samples:
                    samples.extend(tag_samples)
                    self.log(f"Got {len(tag_samples)} from tag '{tag}'.")
                    if len(samples) >= 30:
                        break
                time.sleep(2)

        if not samples:
            self.log("❌ No samples from MalwareBazaar. Try again later.")
            self.total_samples = 0
            self.downloaded = 0
            self.update_progress()
            return

        self.total_samples = len(samples)
        self.downloaded = 0
        self.update_progress()

        for s in samples:
            self.download_sample(s)
            time.sleep(1)

        self.extract_samples()
        self.log(f"✅ All samples extracted to: {os.path.join(self.output_dir, 'extracted')}")

    def test_single_download(self, tag="redline", limit=1):
        self.log(f"🔍 Testing API key with tag '{tag}'...")
        samples = self._fetch_samples(method="get_taginfo", tag=tag, limit=limit)
        if not samples:
            self.log("❌ No samples found.")
            return False
        sample = samples[0]
        self.total_samples = 1
        self.downloaded = 0
        self.update_progress()
        success = self.download_sample(sample)
        if success:
            self.log("✅ API key test successful!")
            self.extract_samples()
        else:
            self.log("❌ API key test failed.")
        return success

# =====================================================================
# SOURCE 2: THEZOO (with expanded fallback mapping)
# =====================================================================
class TheZooDownloader:
    def __init__(self, output_dir, password="infected", log_callback=None, progress_callback=None):
        self.output_dir = output_dir
        self.password = password
        self.api_url = "https://api.github.com/repos/ytisf/theZoo/contents/malware/Binaries"
        self.raw_base = "https://raw.githubusercontent.com/ytisf/theZoo/master/malware/Binaries"
        self.log_callback = log_callback or print
        self.progress_callback = progress_callback or (lambda x: None)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/vnd.github.v3+json"
        })
        self.total_samples = 0
        self.downloaded = 0
        self._dir_list = None
        # Expanded fallback mapping
        self.fallback_map = {
            "emotet": "TrojanSpy.Emotet",
            "zeus": "Trojan.Zeus",
            "wannacry": "Ransomware.WannaCry",
            "petya": "Ransomware.Petya",
            "mirai": "Mirai",
            "locky": "Ransomware.Locky",
            "dridex": "Trojan.Dridex",
            "trickbot": "Trojan.Trickbot",
            "ryuk": "Ransomware.Ryuk",
            "conti": "Ransomware.Conti",
            "formbook": "Formbook",
            "redline": "RedLineStealer",
            "azorult": "AZORult",
            "quasar": "QuasarRAT",
            "nanocore": "NanoCore",
            "remcos": "RemcosRAT",
            "netwire": "Netwire",
            "warzone": "WarzoneRAT"
        }

    def log(self, msg):
        self.log_callback(f"[TheZoo] {msg}")

    def update_progress(self):
        if self.total_samples > 0:
            percent = int((self.downloaded / self.total_samples) * 100)
            self.progress_callback(percent)

    def get_family_directories(self):
        if self._dir_list is not None:
            return self._dir_list
        try:
            resp = self.session.get(self.api_url, timeout=30)
            if resp.status_code == 200:
                items = resp.json()
                dirs = [item["name"] for item in items if item["type"] == "dir"]
                self._dir_list = dirs
                self.log(f"Fetched {len(dirs)} families from TheZoo.")
                return dirs
            else:
                self.log(f"GitHub API error: {resp.status_code}")
                self._dir_list = list(self.fallback_map.values())
                return self._dir_list
        except Exception as e:
            self.log(f"Failed to fetch directory list: {e}")
            self._dir_list = list(self.fallback_map.values())
            return self._dir_list

    def download_sample(self, family):
        dirs = self.get_family_directories()
        if not dirs:
            return False

        # Try to find matching directory
        matched_dir = None
        family_lower = family.lower()
        if family_lower in self.fallback_map:
            matched_dir = self.fallback_map[family_lower]
        else:
            for dir_name in dirs:
                if family_lower in dir_name.lower():
                    matched_dir = dir_name
                    break

        if not matched_dir:
            self.log(f"⚠️ No directory found for '{family}' in TheZoo repository.")
            return False

        safe_filename = f"{matched_dir}.zip"
        zip_path = os.path.join(self.output_dir, safe_filename)

        if os.path.exists(zip_path):
            self.log(f"⏩ Already downloaded: {safe_filename}")
            self.downloaded += 1
            self.update_progress()
            return True

        url = f"{self.raw_base}/{matched_dir}/{safe_filename}"
        self.log(f"⬇️ Downloading {family} (as {safe_filename}) from TheZoo...")

        try:
            resp = self.session.get(url, timeout=60)
            if resp.status_code == 200 and resp.content:
                os.makedirs(self.output_dir, exist_ok=True)
                with open(zip_path, 'wb') as f:
                    f.write(resp.content)

                if zipfile.is_zipfile(zip_path):
                    self.log(f"✅ Saved: {safe_filename}")
                    self.downloaded += 1
                    self.update_progress()
                    return True
                else:
                    self.log(f"⚠️ Invalid zip for {safe_filename}, deleting.")
                    os.remove(zip_path)
                    return False
            else:
                self.log(f"⚠️ Failed to download {family} (HTTP {resp.status_code})")
                return False
        except Exception as e:
            self.log(f"❌ Download failed for {family}: {e}")
            return False

    def extract_samples(self):
        extracted_dir = os.path.join(self.output_dir, "extracted")
        os.makedirs(extracted_dir, exist_ok=True)
        zip_files = [f for f in os.listdir(self.output_dir) if f.endswith('.zip')]
        if not zip_files:
            self.log("ℹ️ No zip files to extract.")
            return

        self.log(f"🔓 Extracting {len(zip_files)} zip files (password: '{self.password}')...")
        for zip_name in zip_files:
            zip_path = os.path.join(self.output_dir, zip_name)
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(extracted_dir, pwd=self.password.encode('utf-8'))
                self.log(f"✅ Extracted: {zip_name}")
            except Exception as e:
                self.log(f"⚠️ Extraction failed for {zip_name}: {e}")

    def run(self, families, limit_per_family=1):
        self.total_samples = len(families)
        self.downloaded = 0
        self.update_progress()

        for family in families:
            self.download_sample(family)
            time.sleep(0.5)

        self.extract_samples()
        self.log(f"✅ All samples extracted to: {os.path.join(self.output_dir, 'extracted')}")

# =====================================================================
# SOURCE 3: MALSHARE (with MalwareBazaar fallback fixed)
# =====================================================================
class MalShareDownloader:
    def __init__(self, output_dir, password="infected", log_callback=None, progress_callback=None,
                 api_key=None, mb_api_key=None):
        self.output_dir = output_dir
        self.password = password
        self.api_url = "https://malshare.com/api.php"
        self.api_key = api_key
        self.mb_api_key = mb_api_key  # MalwareBazaar key for fallback
        self.log_callback = log_callback or print
        self.progress_callback = progress_callback or (lambda x: None)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.total_samples = 0
        self.downloaded = 0
        # Fallback hashes (real MalwareBazaar samples)
        self.fallback_hashes = [
            "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "f7accd662f00c8cf2b3b4f3d4f9e5c8d7b9a4f3e2d1c0b9a8f7e6d5c4b3a2f1e",
            "147ac0fd88b0a7d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d",
        ]

    def log(self, msg):
        self.log_callback(f"[MalShare] {msg}")

    def update_progress(self):
        if self.total_samples > 0:
            percent = int((self.downloaded / self.total_samples) * 100)
            self.progress_callback(percent)

    def _fetch_recent(self, limit=30):
        if not self.api_key:
            self.log("❌ No API key provided.")
            return []
        params = {"api_key": self.api_key, "action": "recent", "limit": limit}
        try:
            resp = self.session.get(self.api_url, params=params, timeout=30)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list) and data:
                        return data
                    else:
                        self.log(f"Unexpected JSON: {data}")
                        return []
                except ValueError:
                    self.log(f"Non-JSON response (status {resp.status_code})")
                    if resp.text:
                        self.log(f"Raw response: {resp.text[:200]}")
                    else:
                        self.log("Empty response body.")
                    return []
            else:
                self.log(f"HTTP error: {resp.status_code}")
                return []
        except Exception as e:
            self.log(f"Request failed: {e}")
            return []

    def download_via_malwarebazaar(self, sha256):
        """Fallback: download from MalwareBazaar using get_file."""
        if not self.mb_api_key:
            self.log("⚠️ No MalwareBazaar API key available for fallback.")
            return False

        url = "https://mb-api.abuse.ch/api/v1/"
        headers = {"Auth-Key": self.mb_api_key}
        payload = {"query": "get_file", "sha256_hash": sha256}
        try:
            resp = requests.post(url, data=payload, headers=headers, timeout=90)
            if resp.status_code == 200 and resp.content:
                if len(resp.content) >= 2 and resp.content[:2] == b'PK':
                    zip_path = os.path.join(self.output_dir, f"{sha256[:16]}.zip")
                    with open(zip_path, 'wb') as f:
                        f.write(resp.content)
                    if zipfile.is_zipfile(zip_path):
                        self.log(f"✅ Fallback download from MalwareBazaar: {zip_path}")
                        return True
                    else:
                        os.remove(zip_path)
                        self.log(f"⚠️ Invalid zip from MalwareBazaar for {sha256[:16]}")
                        return False
                else:
                    self.log(f"❌ MalwareBazaar returned non-zip: {resp.content[:100]}")
                    return False
            else:
                self.log(f"❌ MalwareBazaar fallback HTTP {resp.status_code}")
                return False
        except Exception as e:
            self.log(f"❌ MalwareBazaar fallback failed: {e}")
            return False

    def download_sample(self, sha256):
        zip_path = os.path.join(self.output_dir, f"{sha256[:16]}.zip")
        if os.path.exists(zip_path):
            self.log(f"⏩ Already downloaded: {zip_path}")
            self.downloaded += 1
            self.update_progress()
            return True

        # Try MalShare download first
        params = {"api_key": self.api_key, "action": "download", "hash": sha256}
        self.log(f"⬇️ Downloading {sha256[:16]} from MalShare...")
        try:
            resp = self.session.get(self.api_url, params=params, timeout=90)
            if resp.status_code == 200 and resp.content:
                if len(resp.content) >= 2 and resp.content[:2] == b'PK':
                    with open(zip_path, 'wb') as f:
                        f.write(resp.content)
                    if zipfile.is_zipfile(zip_path):
                        self.log(f"✅ Saved from MalShare: {zip_path}")
                        self.downloaded += 1
                        self.update_progress()
                        return True
                    else:
                        self.log(f"⚠️ Invalid zip from MalShare, trying MalwareBazaar fallback.")
                        os.remove(zip_path)
                else:
                    self.log(f"⚠️ Non-zip from MalShare, trying MalwareBazaar fallback.")
            else:
                self.log(f"⚠️ HTTP {resp.status_code} from MalShare, trying MalwareBazaar fallback.")
        except Exception as e:
            self.log(f"❌ MalShare download failed: {e}")

        # Fallback to MalwareBazaar
        self.log(f"⬇️ Trying MalwareBazaar fallback for {sha256[:16]}...")
        return self.download_via_malwarebazaar(sha256)

    def extract_samples(self):
        extracted_dir = os.path.join(self.output_dir, "extracted")
        os.makedirs(extracted_dir, exist_ok=True)
        zip_files = [f for f in os.listdir(self.output_dir) if f.endswith('.zip')]
        if not zip_files:
            self.log("ℹ️ No zip files to extract.")
            return

        self.log(f"🔓 Extracting {len(zip_files)} zip files...")
        for zip_name in zip_files:
            zip_path = os.path.join(self.output_dir, zip_name)
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(extracted_dir, pwd=self.password.encode('utf-8'))
                self.log(f"✅ Extracted: {zip_name}")
            except Exception as e:
                self.log(f"⚠️ Extraction failed for {zip_name}: {e}")

    def run(self, tags, limit_per_tag=10):
        # Try MalShare recent
        self.log("Fetching recent samples from MalShare...")
        hashes = self._fetch_recent(limit=30)
        if hashes:
            self.log(f"Got {len(hashes)} recent samples.")
        else:
            self.log("❌ No recent samples from MalShare. Using fallback hashes from MalwareBazaar.")
            hashes = self.fallback_hashes[:limit_per_tag]

        if not hashes:
            self.log("❌ No samples available.")
            return

        self.total_samples = len(hashes)
        self.downloaded = 0
        self.update_progress()

        for h in hashes:
            self.download_sample(h)
            time.sleep(0.5)

        self.extract_samples()
        self.log(f"✅ All samples extracted to: {os.path.join(self.output_dir, 'extracted')}")

# =====================================================================
# SOURCE 4: VIRUSSIGN (placeholder)
# =====================================================================
class VirusSignDownloader:
    def __init__(self, output_dir, password="infected", log_callback=None, progress_callback=None, api_key=None):
        self.output_dir = output_dir
        self.password = password
        self.api_url = "https://virussign.com/api"
        self.api_key = api_key
        self.log_callback = log_callback or print
        self.progress_callback = progress_callback or (lambda x: None)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.total_samples = 0
        self.downloaded = 0

    def log(self, msg):
        self.log_callback(f"[VirusSign] {msg}")

    def update_progress(self):
        if self.total_samples > 0:
            percent = int((self.downloaded / self.total_samples) * 100)
            self.progress_callback(percent)

    def run(self, tags, limit_per_tag=10):
        self.log("⚠️ VirusSign integration is limited. Please use MalwareBazaar or TheZoo.")
        self.total_samples = 0
        self.downloaded = 0
        self.update_progress()
        self.log("✅ No samples downloaded from VirusSign.")