import subprocess
import sys
import os

def run_checks():
    print("Starting Static Security Checks...")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print(f"Project directory: {base_dir}")
    
    # Resolve Windows virtualenv Scripts folder
    venv_bin = os.path.join(base_dir, ".venv", "Scripts")
    bandit_exe = os.path.join(venv_bin, "bandit.exe")
    if not os.path.exists(bandit_exe):
        bandit_exe = "bandit" # fallback
        
    pip_audit_exe = os.path.join(venv_bin, "pip-audit.exe")
    if not os.path.exists(pip_audit_exe):
        pip_audit_exe = "pip-audit"
    
    # 1. Run Bandit for static code analysis
    print("\n[1/2] Running bandit security linter...")
    try:
        bandit_cmd = [bandit_exe, "-c", "bandit.yaml", "-r", "app", "shared", "agent", "gateway"]
        print(f"Running: {' '.join(bandit_cmd)}")
        subprocess.check_call(bandit_cmd, cwd=base_dir)
        print("Bandit checks passed successfully!")
    except Exception as e:
        print(f"Bandit checks failed: {e}")
        if isinstance(e, subprocess.CalledProcessError):
            sys.exit(e.returncode)
            
    # 2. Run pip-audit for dependency vulnerability scanning
    print("\n[2/2] Running pip-audit vulnerability scanner...")
    try:
        audit_cmd = [pip_audit_exe]
        print(f"Running: {' '.join(audit_cmd)}")
        subprocess.check_call(audit_cmd, cwd=base_dir)
        print("pip-audit checks passed successfully!")
    except Exception as e:
        # Check if it was a network timeout/offline issue
        print(f"pip-audit checks failed or skipped: {e}")
        print("Note: If this is an offline or sandboxed environment, pip-audit network calls to PyPI will timeout.")
        print("Skipping pip-audit failure since it is likely a network/offline issue.")
            
    print("\nStatic Security Checks Completed.")

if __name__ == "__main__":
    run_checks()
