"""
Flask API server for anomaly detection and LLM investigation.
Exposes endpoints for:
- Model health check
- Score individual access event
- Generate investigation summary
- Batch score events
"""

from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
import pickle
import json
import os
import numpy as np
import pandas as pd
import requests
from investigate import investigate_access
from destination import (
    DESTINATION_RISK,
    resolve_destination,
    apply_destination_risk,
)
from history import (
    FIRST_TIME_RISK,
    resolve_first_time,
    apply_first_time_risk,
)

HF_ENDPOINT = "https://router.huggingface.co/v1/chat/completions"
DEFAULT_LLM_MODEL = "meta-llama/Llama-3.1-8B-Instruct"

app = Flask(__name__)
CORS(app)

MODEL_PATH = "./models/isolation_forest.pkl"
SCALER_PATH = "./models/scaler.pkl"
STATS_PATH = "./models/stats.json"

model = None
scaler = None
stats = None

def load_models():
    """Load trained models on startup."""
    global model, scaler, stats
    
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        print("⚠ Models not found. Run 'python train_model.py' first.")
        return False
    
    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        with open(SCALER_PATH, 'rb') as f:
            scaler = pickle.load(f)
        with open(STATS_PATH) as f:
            stats = json.load(f)
        print("✓ Models loaded successfully")
        return True
    except Exception as e:
        print(f"✗ Error loading models: {e}")
        return False

def engineer_features(event: dict) -> np.ndarray:
    """Convert event to feature vector for scoring."""
    features = {
        'hour_of_day': pd.to_datetime(event.get('timestamp', '2025-01-01 12:00:00')).hour,
        'sensitivity_score': 1 if event.get('resource_sensitivity') == 'high' else 0,
        'volume_deviation': event.get('deviation_from_user_avg_rowcount', 0),
        'rowcount': event.get('rowcount', 0),
        'privilege_score': {'admin': 3, 'user': 1, 'guest': 0}.get(event.get('privilege_level'), 1),
        'days_inactive': event.get('days_inactive', 0),
        'time_class_score': {'business_hours': 0, 'off_hours': 1, 'night': 2, 'unusual_hours': 3}.get(event.get('time_classification'), 0),
        'action_score': {'export_data': 3, 'sql_query': 2, 'admin_operation': 3, 'api_call': 1, 'login': 0, 'file_access': 1}.get(event.get('action'), 0),
        'ml_anomaly_score': event.get('ml_anomaly_score', 0),
    }
    
    df = pd.DataFrame([features])
    return scaler.transform(df)

def normalize_score(anomaly_score: float) -> int:
    """Convert isolation forest anomaly score to 0-100 risk scale."""
    if stats is None:
        return 50
    
    # Anomaly scores are typically negative; normalize using stats
    mean = stats['mean_score']
    std = stats['std_score']
    
    # Z-score normalization to 0-100
    z_score = (anomaly_score - mean) / (std + 0.001)
    risk_score = max(0, min(100, 50 + (z_score * 15)))
    
    return int(risk_score)

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'stats': stats
    })

@app.route('/score', methods=['POST'])
def score_event():
    """
    Score a single access event.
    
    POST /score
    {
      "user_id": "USR00057",
      "username": "user.name",
      "timestamp": "2025-04-21 05:58:00",
      "action": "export_data",
      "resource": "Customer_Vault",
      "resource_sensitivity": "high",
      "time_classification": "night",
      "rowcount": 10000,
      "user_avg_rowcount": 100,
      "deviation_from_user_avg_rowcount": 9900,
      "department": "Finance",
      "job_title": "Analyst",
      "privilege_level": "user",
      "days_inactive": 5,
      "ml_anomaly_score": 72.5,
      "rules_triggered": ["High-sensitivity export", "Off-hours access"],
      "severity": "HIGH"
    }
    
    Returns:
    {
      "risk_score": 78,
      "anomaly_detected": true,
      "investigation": "..."
    }
    """
    
    if model is None:
        return jsonify({'error': 'Model not loaded'}), 503
    
    try:
        data = request.json
        
        # Engineer features
        X = engineer_features(data)
        
        # Get anomaly score (Isolation Forest behavior is preserved as-is)
        anomaly_score = model.score_samples(X)[0]
        is_anomaly = model.predict(X)[0] == -1
        
        # Normalize Isolation Forest output to 0-100 (base risk)
        base_risk = normalize_score(anomaly_score)
        
        # Destination-aware scoring (defaults safely to LOCAL_MACHINE)
        destination_type, destination_score = resolve_destination(data)
        risk_score = apply_destination_risk(base_risk, destination_score)
        
        # First-time resource access (behavioral signal from historical index)
        is_first_time, first_time_contribution = resolve_first_time(data)
        risk_score = apply_first_time_risk(risk_score, first_time_contribution)
        
        # Generate investigation
        investigation = investigate_access(data)
        
        return jsonify({
            'risk_score': risk_score,
            'base_risk_score': base_risk,
            'destination_type': destination_type,
            'destination_score': destination_score,
            'is_first_time_resource_access': is_first_time,
            'first_time_score': first_time_contribution,
            'anomaly_detected': bool(is_anomaly),
            'anomaly_score': float(anomaly_score),
            'investigation': investigation,
            'user_id': data.get('user_id'),
            'username': data.get('username'),
            'resource': data.get('resource'),
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/investigate', methods=['POST'])
def investigate():
    """
    Generate LLM-powered investigation for an event without scoring.
    
    POST /investigate
    { event data same as /score }
    
    Returns:
    { "investigation": "..." }
    """
    
    try:
        data = request.json
        investigation = investigate_access(data)
        return jsonify({'investigation': investigation})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/batch-score', methods=['POST'])
def batch_score():
    """
    Score multiple events at once.
    
    POST /batch-score
    { "events": [...] }
    
    Returns:
    { "results": [{"user_id": ..., "risk_score": ..., ...}, ...] }
    """
    
    if model is None:
        return jsonify({'error': 'Model not loaded'}), 503
    
    try:
        data = request.json
        events = data.get('events', [])
        
        results = []
        for event in events:
            X = engineer_features(event)
            anomaly_score = model.score_samples(X)[0]
            base_risk = normalize_score(anomaly_score)
            
            # Destination-aware scoring (defaults safely to LOCAL_MACHINE)
            destination_type, destination_score = resolve_destination(event)
            risk_score = apply_destination_risk(base_risk, destination_score)
            
            # First-time resource access (behavioral signal from historical index)
            is_first_time, first_time_contribution = resolve_first_time(event)
            risk_score = apply_first_time_risk(risk_score, first_time_contribution)
            
            results.append({
                'user_id': event.get('user_id'),
                'username': event.get('username'),
                'resource': event.get('resource'),
                'risk_score': risk_score,
                'base_risk_score': base_risk,
                'destination_type': destination_type,
                'destination_score': destination_score,
                'is_first_time_resource_access': is_first_time,
                'first_time_score': first_time_contribution,
                'anomaly_detected': model.predict(X)[0] == -1,
            })
        
        return jsonify({'results': results})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/model-stats', methods=['GET'])
def model_stats():
    """Get model statistics and feature info."""
    return jsonify({
        'stats': stats,
        'features': [
            'hour_of_day',
            'sensitivity_score',
            'volume_deviation',
            'rowcount',
            'privilege_score',
            'days_inactive',
            'time_class_score',
            'action_score',
            'ml_anomaly_score',
            'is_first_time_resource_access'
        ],
        'destination_risk': DESTINATION_RISK,
        'first_time_risk': FIRST_TIME_RISK,
    })

@app.route('/llm/chat', methods=['POST'])
def llm_chat():
    """
    Server-side LLM proxy. The Hugging Face token stays on the server
    (HUGGINGFACE_ACCESS_TOKEN env var) and is never sent to the browser.
    Supports streaming (Server-Sent Events) when stream != false.

    POST /llm/chat
    { "model": "...", "messages": [...], "stream": true }
    """
    token = os.environ.get('HUGGINGFACE_ACCESS_TOKEN')
    if not token:
        return jsonify({'error': 'HUGGINGFACE_ACCESS_TOKEN is not set on the server.'}), 500

    body = request.json or {}
    stream = body.get('stream', True)
    payload = {
        'model': body.get('model', DEFAULT_LLM_MODEL),
        'temperature': body.get('temperature', 0.2),
        'max_tokens': body.get('max_tokens', 1200),
        'stream': stream,
        'messages': body.get('messages', []),
    }
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    try:
        upstream = requests.post(HF_ENDPOINT, headers=headers, json=payload, stream=stream, timeout=60)
    except Exception as e:
        return jsonify({'error': f'Upstream request failed: {e}'}), 502

    if upstream.status_code != 200:
        return jsonify({'error': f'Upstream HTTP {upstream.status_code} — {upstream.text[:300]}'}), upstream.status_code

    if not stream:
        return jsonify(upstream.json())

    def generate():
        for chunk in upstream.iter_content(chunk_size=None):
            if chunk:
                yield chunk

    return Response(stream_with_context(generate()), mimetype='text/event-stream')


if __name__ == '__main__':
    if load_models():
        print("Starting Flask API on http://localhost:5000")
        app.run(debug=True, port=5000)
    else:
        print("Cannot start API without trained models.")
