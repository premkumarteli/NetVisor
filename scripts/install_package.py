#!/usr/bin/env python3
"""
Install NetVisor as a proper Python package to fix import issues.
This script removes the need for sys.path manipulation.
"""

import subprocess
import sys
from pathlib import Path

def main():
    """Install the NetVisor package in development mode."""
    project_root = Path(__file__).resolve().parent.parent
    
    print(f"Installing NetVisor package from: {project_root}")
    
    # Install in development mode with pip
    cmd = [sys.executable, "-m", "pip", "install", "-e", str(project_root)]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print("✅ NetVisor package installed successfully!")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install NetVisor package: {e}")
        print(f"Error output: {e.stderr}")
        sys.exit(1)

if __name__ == "__main__":
    main()
