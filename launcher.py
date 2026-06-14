import subprocess
import time
import webbrowser
import os
import sys

print("🚀 SentinelIQ - Starting Backend & Frontend...\n")

# Install Python deps
print("📦 Installing Python dependencies...")
backend_venv_cmd = (
    "cd backend && "
    "python -m venv venv && "
    f"{'venv\\Scripts\\activate.bat' if sys.platform == 'win32' else 'source venv/bin/activate'} && "
    "pip install -r requirements.txt"
)

# Start backend
print("⚙️  Starting ML Backend...")
backend_cmd = (
    "cd backend && "
    f"{'venv\\Scripts\\activate.bat' if sys.platform == 'win32' else 'source venv/bin/activate'} && "
    "python train_model.py && python app.py"
)
backend_proc = subprocess.Popen(
    backend_cmd,
    shell=True,
    stdout=subprocess.DEVNULL
)

print("⏳ Backend loading (8 sec)...")
time.sleep(8)

# Start frontend
print("🎨 Starting React Frontend...")
frontend_proc = subprocess.Popen("npm run dev", shell=True)

print("\n✅ System Started!")
print("📱 Opening dashboard in 3 seconds...")
time.sleep(3)
webbrowser.open("http://localhost:5173")

try:
    frontend_proc.wait()
except KeyboardInterrupt:
    print("\n🛑 Shutting down...")
    backend_proc.terminate()
    frontend_proc.terminate()