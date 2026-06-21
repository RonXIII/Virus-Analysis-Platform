# core/ml_detector.py
import os
import numpy as np
import pickle
from collections import Counter
from typing import Tuple, Optional, Callable
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

class MLDetector:
    def __init__(self, model_path: str = "./models/malware_model.pkl"):
        self.model_path = model_path
        self.model = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            with open(self.model_path, 'rb') as f:
                data = pickle.load(f)
                self.model = data.get('model')

    def save_model(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({'model': self.model}, f)

    def extract_features(self, file_path: str) -> np.ndarray:
        with open(file_path, 'rb') as f:
            data = f.read()
        ngrams = Counter(data[i:i+4] for i in range(len(data)-3))
        ngram_features = [ngrams.get(k, 0) for k, _ in ngrams.most_common(200)]
        entropies = []
        for i in range(0, len(data)-255, 128):
            window = data[i:i+256]
            freq = np.zeros(256)
            for b in window:
                freq[b] += 1
            freq = freq / len(window)
            ent = -np.sum(freq * np.log2(freq + 1e-10))
            entropies.append(ent)
        entropy_features = [np.mean(entropies) if entropies else 0,
                            np.std(entropies) if entropies else 0]
        size_features = [len(data), np.mean(list(data)) if data else 0, np.std(list(data)) if data else 0]
        pe_features = [0.0]*5
        try:
            import pefile
            from io import BytesIO
            pe = pefile.PE(data=BytesIO(data))
            pe_features[0] = len(pe.sections)
            for sec in pe.sections:
                sec_data = sec.get_data()[:4096]
                if sec_data:
                    freq = np.zeros(256)
                    for b in sec_data:
                        freq[b] += 1
                    freq /= len(sec_data)
                    pe_features[1] += -np.sum(freq * np.log2(freq + 1e-10))
            pe_features[1] /= len(pe.sections) if pe.sections else 1
            pe_features[2] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
        except:
            pass
        return np.concatenate([ngram_features, entropy_features, size_features, pe_features])

    def train(self, malware_dir: str, benign_dir: str, progress_callback: Optional[Callable[[int], None]] = None):
        malware_files = [os.path.join(malware_dir, f) for f in os.listdir(malware_dir) if f.endswith(('.exe', '.dll', '.sys'))]
        benign_files = [os.path.join(benign_dir, f) for f in os.listdir(benign_dir) if f.endswith(('.exe', '.dll', '.sys'))]

        if len(malware_files) < 3 or len(benign_files) < 3:
            raise ValueError(f"Not enough samples. Malware: {len(malware_files)}, Benign: {len(benign_files)}. Need at least 3 each.")

        X, y = []
        # Load malware
        for i, f in enumerate(malware_files):
            try:
                X.append(self.extract_features(f))
                y.append(1)
            except:
                pass
            if progress_callback:
                progress_callback(int(20 * (i+1) / len(malware_files)))
        # Load benign
        for i, f in enumerate(benign_files):
            try:
                X.append(self.extract_features(f))
                y.append(0)
            except:
                pass
            if progress_callback:
                progress_callback(20 + int(20 * (i+1) / len(benign_files)))
        if len(X) == 0 or len(y) == 0:
            raise ValueError("No valid samples found.")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        if progress_callback:
            progress_callback(60)
        self.model = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1)
        self.model.fit(X_train, y_train)
        if progress_callback:
            progress_callback(80)
        acc = self.model.score(X_test, y_test)
        self.save_model()
        if progress_callback:
            progress_callback(100)
        print(f"Accuracy: {acc:.4f}")

    def predict(self, file_path: str) -> Tuple[int, float]:
        if self.model is None:
            raise ValueError("Model not loaded")
        features = self.extract_features(file_path).reshape(1, -1)
        proba = self.model.predict_proba(features)[0]
        if len(proba) == 1:
            prob = proba[0]
            pred = 1 if prob > 0.5 else 0
        else:
            prob = proba[1]
            pred = 1 if prob > 0.5 else 0
        return pred, float(prob)