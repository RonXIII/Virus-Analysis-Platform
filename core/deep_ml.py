# core/deep_ml.py
import os
import numpy as np
from typing import Optional, Callable
from config import Config

try:
    import tensorflow as tf
    from tensorflow.keras import layers, models
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("⚠️ TensorFlow not installed. Deep learning detector disabled.")

class DeepMalwareDetector:
    def __init__(self, model_path=None):
        self.model_path = model_path or os.path.join(Config.MODELS_DIR, 'cnn_model.h5')
        self.model = None
        self.input_size = 65536
        self._load_model()

    def _load_model(self):
        if not TENSORFLOW_AVAILABLE:
            return
        if os.path.exists(self.model_path):
            try:
                self.model = tf.keras.models.load_model(self.model_path)
                print("✅ Deep learning model loaded successfully.")
            except Exception as e:
                print(f"⚠️ Failed to load deep learning model: {e}")

    def _preprocess(self, raw_bytes: bytes) -> np.ndarray:
        arr = np.frombuffer(raw_bytes[:self.input_size], dtype=np.uint8)
        if len(arr) < self.input_size:
            arr = np.pad(arr, (0, self.input_size - len(arr)), constant_values=0)
        arr = arr.astype(np.float32) / 255.0
        return arr.reshape(1, self.input_size, 1)

    def predict(self, file_path: str):
        if not TENSORFLOW_AVAILABLE or self.model is None:
            return 0, 0.0
        with open(file_path, 'rb') as f:
            data = f.read()
        X = self._preprocess(data)
        try:
            proba = float(self.model.predict(X, verbose=0)[0][0])
            return 1 if proba > 0.5 else 0, proba
        except Exception as e:
            print(f"❌ Deep learning prediction failed: {e}")
            return 0, 0.0

    @staticmethod
    def build_model(input_shape=(65536, 1)):
        if not TENSORFLOW_AVAILABLE:
            raise RuntimeError("TensorFlow not installed")
        model = models.Sequential([
            layers.Conv1D(64, 128, activation='relu', input_shape=input_shape),
            layers.MaxPooling1D(4),
            layers.Conv1D(128, 64, activation='relu'),
            layers.MaxPooling1D(4),
            layers.Conv1D(256, 32, activation='relu'),
            layers.GlobalAveragePooling1D(),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.5),
            layers.Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model

    def train(self, malware_dir: str, benign_dir: str, epochs=10, sample_limit=1000,
              progress_callback: Optional[Callable[[int], None]] = None):
        if not TENSORFLOW_AVAILABLE:
            print("❌ TensorFlow not installed. Cannot train CNN.")
            if progress_callback:
                progress_callback(0)
            return

        malware_files = [os.path.join(malware_dir, f) for f in os.listdir(malware_dir) if f.endswith(('.exe', '.dll', '.sys'))][:sample_limit]
        benign_files = [os.path.join(benign_dir, f) for f in os.listdir(benign_dir) if f.endswith(('.exe', '.dll', '.sys'))][:sample_limit]

        if len(malware_files) < 5 or len(benign_files) < 5:
            print(f"❌ Not enough samples. Malware: {len(malware_files)}, Benign: {len(benign_files)}. Need at least 5 each.")
            if progress_callback:
                progress_callback(0)
            return

        X, y = [], []
        total = len(malware_files) + len(benign_files)

        # Load malware
        for i, f in enumerate(malware_files):
            try:
                with open(f, 'rb') as fd:
                    X.append(self._preprocess(fd.read())[0])
                    y.append(1)
            except Exception as e:
                print(f"⚠️ Failed to load malware {f}: {e}")
            if progress_callback:
                progress_callback(int(20 * (i+1) / len(malware_files)))

        # Load benign
        for i, f in enumerate(benign_files):
            try:
                with open(f, 'rb') as fd:
                    X.append(self._preprocess(fd.read())[0])
                    y.append(0)
            except Exception as e:
                print(f"⚠️ Failed to load benign {f}: {e}")
            if progress_callback:
                progress_callback(20 + int(20 * (i+1) / len(benign_files)))

        if len(X) < 10:
            print("❌ Not enough samples to train. Need at least 10 total.")
            if progress_callback:
                progress_callback(0)
            return

        X = np.array(X)
        y = np.array(y)
        if progress_callback:
            progress_callback(60)
        self.model = self.build_model()
        print(f"🔄 Training CNN on {len(X)} samples for {epochs} epochs...")
        self.model.fit(X, y, epochs=epochs, validation_split=0.2, verbose=0)
        if progress_callback:
            progress_callback(80)
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        self.model.save(self.model_path)
        if progress_callback:
            progress_callback(100)
        print(f"✅ Model saved to {self.model_path}")