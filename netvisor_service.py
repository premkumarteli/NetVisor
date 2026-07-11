import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.append(str(PROJECT_ROOT))

# Resolve site-packages and pywin32 directories to prevent ModuleNotFoundError
venv_site_packages = PROJECT_ROOT / ".venv" / "Lib" / "site-packages"
if venv_site_packages.exists():
    sys.path.append(str(venv_site_packages))
    sys.path.append(str(venv_site_packages / "win32"))
    sys.path.append(str(venv_site_packages / "win32" / "lib"))
    sys.path.append(str(venv_site_packages / "win32com"))

import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import os
import threading
import time
import logging

# Set up logging to a file
LOG_DIR = PROJECT_ROOT / "runtime" / "agent" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "netvisor_service.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("NetVisorService")

# Load dotenv
from dotenv import load_dotenv
load_dotenv(dotenv_path=PROJECT_ROOT / ".env")

from agent.main import NetworkAgent

class NetVisorAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetVisorAgent"
    _svc_display_name_ = "NetVisor Hybrid SOC Agent"
    _svc_description_ = "NetVisor endpoint traffic analysis, threat detection, and DPI inspection agent."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.agent = None

    def SvcStop(self):
        logger.info("Service stop requested.")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        if self.agent:
            logger.info("Stopping NetVisor agent...")
            self.agent.is_running = False
            # Safely stop capture backend
            if hasattr(self.agent, "capture_backend"):
                self.agent.capture_backend.stop()
            if hasattr(self.agent, "web_inspection"):
                self.agent.web_inspection.stop()
            self.agent.flow_manager.stop()
            self.agent.device_inventory.save_inventory()
        logger.info("Service stop finished.")

    def SvcDoRun(self):
        logger.info("Service is starting...")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        
        # Report running status to SCM immediately
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        
        # Start the main agent runner in a daemon thread
        threading.Thread(target=self.run_agent, name="AgentThread", daemon=True).start()
        
        # Wait until stop event is signaled
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        logger.info("Service stopped.")

    def run_agent(self):
        try:
            config_path = PROJECT_ROOT / "config" / "agent.json"
            logger.info(f"Initializing NetworkAgent with config: {config_path}")
            
            # Monkeypatch stop() method of NetworkAgent to avoid calling sys.exit(0)
            def service_friendly_stop(agent_self):
                agent_self.is_running = False
                if hasattr(agent_self, "capture_backend"):
                    agent_self.capture_backend.stop()
                if hasattr(agent_self, "web_inspection"):
                    agent_self.web_inspection.stop()
                agent_self.flow_manager.stop()
                agent_self.device_inventory.save_inventory()
            
            NetworkAgent.stop = service_friendly_stop

            self.agent = NetworkAgent(config_path=config_path, start_background_workers=True)
            logger.info("Starting NetworkAgent...")
            self.agent.start()
        except Exception as exc:
            logger.exception("Agent thread crashed:")
            # If the agent thread crashes, trigger stop of the service so SCM knows
            win32event.SetEvent(self.hWaitStop)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Service SCM mode
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(NetVisorAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Command-line installation / management mode
        win32serviceutil.HandleCommandLine(NetVisorAgentService)
