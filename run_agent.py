from pathlib import Path
import sys

from dotenv.main import load_dotenv

from agent.security.integrity import verify_agent_code_integrity
from agent.main import main as agent_main

if __name__ == "__main__":
    load_dotenv()
    
    # Boot-time Code Integrity Check
    bundle_root = Path(__file__).resolve().parent
    integrity = verify_agent_code_integrity(bundle_root)
    if integrity["status"] == "failed":
        print("[-] SECURITY CRITICAL: Code integrity check failed!")
        for finding in integrity.get("findings", []):
            print(f"    - {finding.get('message')}")
        sys.exit(1)
    elif integrity["status"] == "unsigned_dev":
        print("[*] WARNING: Agent running in unsigned development mode. Code integrity is not enforced.")
    else:
        print(f"[+] Code integrity verified successfully (Manifest hash: {integrity.get('manifest_hash')[:8]})")

    config_path = Path(__file__).resolve().parent / "config" / "agent.json"
    if not config_path.exists():
        raise FileNotFoundError(f"Missing agent config: {config_path}")

    print(f"[*] Starting SOC Agent using config: {config_path}")
    agent_main(config_path)
