import os
import subprocess
import sys

def main():
    print("[*] Starting Sentinel AI Safety Governance Layer...")
    backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
    
    # ensure dependencies
    print("[*] Checking dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"], cwd=backend_dir)
    except subprocess.CalledProcessError:
        print("[!] Warning: Failed to install some dependencies. Starting anyway as optional ML modules can gracefully degrade.")
        
    print("[+] Dependencies installed.")
    print("[*] Starting FastAPI server on http://localhost:8000")
    print("[*] Dashboard will be available at http://localhost:8000")
    
    try:
        subprocess.check_call([sys.executable, "-m", "uvicorn", "main:app", "--reload", "--port", "8000"], cwd=backend_dir)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Sentinel.")

if __name__ == "__main__":
    main()
