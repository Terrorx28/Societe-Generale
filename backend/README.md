# SentinelIQ Backend

Isolation Forest + LLM-powered anomaly detection and investigation API.

## Features

- **Isolation Forest Training**: Learn normal user access patterns from historical data
- **Real-time Scoring**: Convert access events to 0-100 risk scores
- **LLM Investigation**: Generate professional risk summaries using OpenAI (with fallback)
- **Batch Processing**: Score multiple events efficiently
- **CORS Enabled**: Ready for frontend integration

## Quick Start

### 1. Install Python 3.9+
Ensure Python is installed on your system.

### 2. Create Virtual Environment
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate  # Windows
# or: source venv/bin/activate  # Mac/Linux
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Train Model
```bash
python train_model.py
```

This reads `src/imports/anomaly_predictions.json` and trains an Isolation Forest on 9 features:
- Hour of day
- Resource sensitivity
- Data volume deviation
- User privilege level
- Days inactive (stale account risk)
- Time classification
- Action type
- ML anomaly score

Output: Models saved to `models/isolation_forest.pkl` and `models/scaler.pkl`

### 5. (Optional but RECOMMENDED) Add Hugging Face API Key for LLM Investigations

**Step 1: Get a Free Hugging Face Token**
1. Sign up (free): https://huggingface.co
2. Go to: Settings → Access Tokens
3. Click "New token" → Generate → Copy token

**Step 2: Create `.env` file**
```bash
cp .env.example .env
```

**Step 3: Add your Hugging Face API key**
Edit `.env` and set:
```bash
HF_API_KEY=hf_your_token_here
```

Replace `hf_your_token_here` with your actual token.

**What This Does:**
- LLM investigations become smarter (NLP-based summaries)
- Uses `meta-llama/Llama-2-7b-chat-hf` model
- Free tier supported, no credit card needed
- If this fails, system automatically falls back to rule-based investigations

**Without HF/OpenAI key?** No problem! The system uses rule-based investigation summaries (still very effective for hackathon).

### 6. Start API Server
```bash
python app.py
```

Server runs on `http://localhost:5000`

## LLM Integration Priority

The system tries LLM providers in this order:

1. **Hugging Face** (recommended) ← Uses Llama-2 chat model
   - Free tier: works great
   - No credit card required
   - Fast enough for hackathon

2. **OpenAI** (fallback)
   - Uses GPT-3.5-turbo
   - Requires API key + credits
   - More sophisticated but slower

3. **Rule-Based** (always available)
   - No API needed
   - Fast, deterministic
   - Good enough for demo

## API Endpoints

### Health Check
```bash
GET /health
```

Returns model status and baseline statistics.

### Score Single Event
```bash
POST /score
Content-Type: application/json

{
  "user_id": "USR00057",
  "username": "john.smith",
  "timestamp": "2025-04-21 03:15:00",
  "action": "export_data",
  "resource": "Customer_Vault",
  "resource_sensitivity": "high",
  "time_classification": "night",
  "rowcount": 50000,
  "user_avg_rowcount": 100,
  "deviation_from_user_avg_rowcount": 49900,
  "department": "Finance",
  "job_title": "Analyst",
  "privilege_level": "user",
  "days_inactive": 5,
  "ml_anomaly_score": 75.2,
  "rules_triggered": ["High-sensitivity export", "Off-hours access"],
  "severity": "HIGH"
}
```

Returns:
```json
{
  "risk_score": 82,
  "anomaly_detected": true,
  "investigation": "[HIGH] - john.smith export with accessed high-sensitivity Customer_Vault; export during night; data volume 50000 rows (typically 100). Monitor for context. Escalate if repeated.",
  "user_id": "USR00057",
  "username": "john.smith",
  "resource": "Customer_Vault"
}
```

### Batch Score Events
```bash
POST /batch-score
Content-Type: application/json

{
  "events": [
    { ... event 1 ... },
    { ... event 2 ... }
  ]
}
```

Returns array of scored events.

### Generate Investigation Only
```bash
POST /investigate
Content-Type: application/json

{ event data ... }
```

Returns just the investigation text.

### Model Statistics
```bash
GET /model-stats
```

Returns baseline stats and feature list.

## Feature Engineering

The backend automatically extracts these features from raw access events:

| Feature | Source | Interpretation |
|---------|--------|-----------------|
| `hour_of_day` | timestamp | 0-23 (unusual hours = higher anomaly) |
| `sensitivity_score` | resource_sensitivity | Binary (high=1, low=0) |
| `volume_deviation` | rowcount vs user_avg | How far from typical (large deviations = anomaly) |
| `rowcount` | raw event data | Absolute access volume |
| `privilege_score` | privilege_level | admin=3, user=1, guest=0 |
| `days_inactive` | user profile | Stale account = higher risk |
| `time_class_score` | time_classification | business_hours=0, night=2 (escalating) |
| `action_score` | action | export/admin=3, query=2, login=0 |
| `ml_anomaly_score` | pre-computed | Original ML model's score |

## Risk Score Mapping

Raw isolation forest anomaly scores are normalized to 0-100 using z-score:

- 0-20: Low risk (normal behavior)
- 21-50: Medium risk (unusual but within bounds)
- 51-75: High risk (significant deviation)
- 76-100: Critical risk (major anomaly)

## LLM Investigation Fallback

If OpenAI API is unavailable or rate-limited, the system automatically generates rule-based summaries:

```
[RISK_LEVEL] - {username} {action} with {risk factors}. {recommended action}
```

This ensures the system is never blocked by external API availability.

## Integration with Frontend

The React frontend calls the Flask API endpoints via HTTP:

```javascript
const response = await fetch('http://localhost:5000/score', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(eventData)
});
const { risk_score, investigation } = await response.json();
```

See `src/app/components/AIAnalystPage.tsx` for integration example.

## Troubleshooting

### Models not found
```
python train_model.py
```

### CORS errors on frontend
Check that Flask app has `CORS(app)` enabled and frontend URL is whitelisted.

### LLM API errors
- Check OpenAI API key in `.env`
- System will automatically fall back to rule-based investigations
- Check `OPENAI_API_KEY` environment variable is set correctly

### Port already in use
Change port in `app.py`: `app.run(port=5001)`

## Next Steps

1. Train the model: `python train_model.py`
2. Start API: `python app.py`
3. Connect frontend in `AIAnalystPage.tsx`
4. Add optional OpenAI key for LLM summaries
