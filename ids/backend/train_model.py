import os
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), "anomaly_model.pkl")

def train_model(contamination=0.01):
    print(f"[INFO] Training ML Model with contamination={contamination}...")
    # Dummy network features [size, port, proto, flags]
    # Normal data profile (web traffic, small/medium packets)
    X_train = np.array([
        [64, 80, 6, 2], [1500, 443, 6, 24], 
        [500, 53, 17, 0], [40, 80, 6, 16],
        [100, 443, 6, 16], [1200, 8080, 6, 24],
        [64, 22, 6, 2], [50, 53, 17, 0]
    ])
    
    # Train Isolation Forest
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(X_train)
    
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
        
    print(f"[SUCCESS] Saved custom ML Model to {MODEL_PATH}")

if __name__ == "__main__":
    train_model()
