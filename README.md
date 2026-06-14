# SentinelIQ - Insider Threat Intelligence Dashboard

SentinelIQ is a specialized security dashboard designed to monitor, identify, and investigate potential insider threats and data access anomalies. It combines chronological event tracking, temporal access matrices (heatmaps), and structured incident reporting with interactive AI-driven forensic analysis.

## Features

- **Threat Overview**: Real-time stats on critical threats, high-risk events, flagged users, and department risk rankings.
- **Active Alerts**: Searchable and filterable dashboard of anomalous access attempts.
- **Event Timeline**: A detailed, date-grouped stream of access events and security logs.
- **Case Files**: Profiles of high-risk users automatically classified by anomaly scoring.
- **Access Heatmap**: A temporal matrix mapping access volume across hours and weekdays.
- **AI Analyst**: Interactive conversational assistant to assess individual threat profiles.
- **Reports**: Auto-generation of board-ready Executive Summaries, Compliance Reports (GDPR/SOX/NIST), and Forensic Incident files.

## Running the Code

### 🚀 One-Click Setup (Recommended for Hackathon)

**Option 1: Auto-Launcher Script**
```bash
python launcher.py
```
This automatically:
- Starts Python backend (Isolation Forest model training & Flask API)
- Starts React frontend (Vite dev server)
- Opens browser to http://localhost:5173

**Option 2: Manual Setup**

**Terminal 1 — Start Backend:**
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate              # Windows
# or: source venv/bin/activate       # Mac/Linux
pip install -r requirements.txt
python train_model.py                # Trains ML model (~2-5 sec)
python app.py                        # Starts Flask API on localhost:5000
```

**Terminal 2 — Start Frontend:**
```bash
npm install
npm run dev                          # Starts Vite on localhost:5173
```

Open browser: **http://localhost:5173**

### 🤖 Adding LLM Investigations (Hugging Face — RECOMMENDED)

**IMPORTANT**: This is optional but highly recommended for hackathon judges to see advanced features.

**Step 1: Create Hugging Face Account (2 minutes)**
1. Go to https://huggingface.co
2. Sign up (free, no credit card needed)
3. Go to Settings → Access Tokens → New token
4. Copy the token (starts with `hf_`)

**Step 2: Add Token to Backend**
```bash
cd backend
cp .env.example .env
# Edit .env and replace:
# HF_API_KEY=hf_your_token_here
```

**Step 3: Restart Flask**
```bash
python app.py
```

**What Happens:**
- Investigations now use Llama-2 LLM (professional NLP summaries)
- Example output: `[HIGH] - john.smith export with accessed high-sensitivity Customer_Vault; export during night. Investigate immediately.`
- If LLM fails, system automatically falls back to rule-based summaries

**Without LLM?** No problem — rule-based investigations work perfectly for the demo!

### 📊 What You'll See

1. **Dashboard** (first tab)
   - Critical threat counts
   - Risk distribution charts
   - Department rankings

2. **Analytics** (second tab)
   - Feature Analysis: access patterns (time, sensitivity, volume)
   - DLP Prevention panel: shows blocked exports by policy
   - Export & login failure charts

3. **AI Analyst** (third tab)
   - Ask questions like "Who is the most dangerous user?"
   - Get instant AI-powered analysis
   - Click on incidents for detailed forensics

4. **Reports** (fourth tab)
   - Executive Summary (CISO-ready)
   - Incident Reports (forensic detail)
   - Compliance Reports (GDPR/SOX/NIST)

### 🏗️ Project Structure

```
.
├── src/
│   ├── app/
│   │   ├── App.tsx                 # Main dashboard
│   │   └── components/
│   │       ├── AIAnalystPage.tsx   # AI chat with LLM
│   │       └── ui/                 # React components
│   ├── imports/
│   │   └── anomaly_predictions.json # Sample security data
│   └── styles/
│
├── backend/
│   ├── train_model.py              # Isolation Forest training
│   ├── app.py                      # Flask API server
│   ├── investigate.py              # LLM integration (HF/OpenAI)
│   ├── requirements.txt
│   └── README.md                   # Backend documentation
│
├── launcher.py                     # One-click start script
└── package.json
```

### 🔧 Technology Stack

**Frontend:**
- React + TypeScript
- Vite (build tool)
- Recharts (visualizations)
- Radix UI components

**Backend:**
- Python 3.9+
- Scikit-learn (Isolation Forest)
- Flask + CORS
- Hugging Face Inference API (LLM)

**ML:**
- Isolation Forest: Anomaly detection on 9 features
- Feature engineering: time, sensitivity, volume deviation, privilege, inactivity
- Risk scoring: 0-100 scale

### 🧠 How It Works

1. **Data Load**: Historical access events loaded from JSON
2. **Feature Extraction**: 9 features engineered per event (time, sensitivity, volume, etc.)
3. **Model Training**: Isolation Forest learns "normal" access patterns
4. **Scoring**: Each event scored 0-100 risk scale
5. **Investigation**: LLM generates professional risk summary (HF/OpenAI/fallback)
6. **Visualization**: Dashboard shows threats, patterns, and incidents

### Notes

- `src/imports/anomaly_predictions.json` and `src/imports/evaluation_metrics.json` are pre-generated for the static frontend.
- Backend API runs locally (not deployed) for live ML scoring and LLM investigations.
- For deployment, build frontend with `npm run build` and deploy `dist/` folder to any static host (GitHub Pages, Vercel, etc.)
- Backend runs as standalone Flask API on your server or local machine.
