"""
Isolation Forest training script.
Trains on historical anomaly prediction data to learn normal user access patterns.
"""

import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os

DATA_PATH = "../src/imports/anomaly_predictions.json"
MODEL_PATH = "./models/isolation_forest.pkl"
SCALER_PATH = "./models/scaler.pkl"

def load_data():
    """Load anomaly predictions JSON."""
    with open(DATA_PATH) as f:
        return json.load(f)

def engineer_features(df):
    """Extract features for anomaly detection."""
    features = pd.DataFrame()
    
    # Time feature: convert to hour of day
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    features['hour_of_day'] = df['timestamp'].dt.hour
    
    # Data sensitivity: encode high/low
    features['sensitivity_score'] = (df['resource_sensitivity'] == 'high').astype(int)
    
    # Volume deviation
    features['volume_deviation'] = df['deviation_from_user_avg_rowcount']
    features['rowcount'] = df['rowcount']
    
    # User privilege level
    privilege_map = {'admin': 3, 'user': 1, 'guest': 0}
    features['privilege_score'] = df['privilege_level'].map(privilege_map).fillna(1)
    
    # Days inactive (stale account risk)
    features['days_inactive'] = df['days_inactive']
    
    # Time classification encoding
    time_map = {'business_hours': 0, 'off_hours': 1, 'night': 2, 'unusual_hours': 3}
    features['time_class_score'] = df['time_classification'].map(time_map).fillna(0)
    
    # Action type encoding
    action_map = {'export_data': 3, 'sql_query': 2, 'admin_operation': 3, 'api_call': 1, 'login': 0, 'file_access': 1}
    features['action_score'] = df['action'].map(action_map).fillna(0)
    
    # ML anomaly score
    features['ml_anomaly_score'] = df['ml_anomaly_score']
    
    return features.fillna(0), df[['user_id', 'username', 'timestamp', 'resource', 'severity']]

def train_model():
    """Train isolation forest on normal behavior."""
    print("Loading data...")
    data = load_data()
    df = pd.DataFrame(data)
    
    print(f"Total records: {len(df)}")
    print("Engineering features...")
    features, metadata = engineer_features(df)
    
    print("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)
    
    print("Training Isolation Forest...")
    # Use contamination estimate from data (% of anomalies)
    contamination = len(df[df['predicted_anomaly'] == 1]) / len(df)
    model = IsolationForest(
        contamination=min(contamination, 0.3),
        random_state=42,
        n_estimators=100
    )
    model.fit(X_scaled)
    
    # Save models
    os.makedirs("./models", exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)
    
    # Compute baseline statistics
    anomaly_scores = model.score_samples(X_scaled)
    predictions = model.predict(X_scaled)
    
    stats = {
        'mean_score': float(np.mean(anomaly_scores)),
        'std_score': float(np.std(anomaly_scores)),
        'min_score': float(np.min(anomaly_scores)),
        'max_score': float(np.max(anomaly_scores)),
        'anomaly_count': int(np.sum(predictions == -1)),
        'normal_count': int(np.sum(predictions == 1)),
    }
    
    with open('./models/stats.json', 'w') as f:
        json.dump(stats, f)
    
    print(f"✓ Model saved to {MODEL_PATH}")
    print(f"✓ Scaler saved to {SCALER_PATH}")
    print(f"✓ Stats: {stats}")
    print("\nFeature columns:", features.columns.tolist())

if __name__ == '__main__':
    train_model()
