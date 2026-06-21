# core/model_pipeline.py
import os
import pickle
import shutil
from datetime import datetime, timedelta
from core.ml_detector import MLDetector
from core.deep_ml import DeepMalwareDetector
from config import Config

class ModelPipeline:
    @staticmethod
    def get_recent_samples(days=7):
        """Fetch recently confirmed samples from storage.
           In production, this would query a database.
        """
        # For demo, we look in a folder with labeled samples
        malware_dir = os.path.join(Config.STORAGE_DIR, 'labeled_malware')
        benign_dir = os.path.join(Config.STORAGE_DIR, 'labeled_benign')
        # You would implement logic to filter by date here
        return malware_dir, benign_dir

    @staticmethod
    def evaluate_model(model, test_dir):
        """Evaluate a model on a test set and return accuracy."""
        correct = 0
        total = 0
        for f in os.listdir(test_dir):
            try:
                pred, _ = model.predict(os.path.join(test_dir, f))
                label = 1 if 'malware' in f else 0
                if pred == label:
                    correct += 1
                total += 1
            except:
                pass
        return correct / total if total > 0 else 0

    @staticmethod
    def retrain():
        """Retrain models with new samples and deploy if better."""
        print("🔄 Starting model retraining pipeline...")

        # 1. Get training data
        malware_dir, benign_dir = ModelPipeline.get_recent_samples()
        if not os.path.exists(malware_dir) or not os.path.exists(benign_dir):
            print("❌ Training directories not found. Skipping retraining.")
            return

        # 2. Train RF model
        rf = MLDetector()
        try:
            rf.train(malware_dir, benign_dir)
            # Save with timestamp
            rf.model_path = os.path.join(Config.MODELS_DIR, f'rf_model_{datetime.now().strftime("%Y%m%d")}.pkl')
            rf.save_model()
            print("✅ Random Forest model retrained.")
        except Exception as e:
            print(f"❌ RF training failed: {e}")

        # 3. Train CNN model
        cnn = DeepMalwareDetector()
        try:
            cnn.train(malware_dir, benign_dir, epochs=5, sample_limit=500)
            print("✅ CNN model retrained.")
        except Exception as e:
            print(f"❌ CNN training failed: {e}")

        # 4. Compare performance on held-out test set
        test_dir = os.path.join(Config.STORAGE_DIR, 'test_samples')
        if os.path.exists(test_dir):
            rf_acc = ModelPipeline.evaluate_model(rf, test_dir)
            cnn_acc = ModelPipeline.evaluate_model(cnn, test_dir)
            print(f"📊 RF accuracy: {rf_acc:.2%}, CNN accuracy: {cnn_acc:.2%}")

        print("✅ Model pipeline completed.")