"""
Windows Network Capture Adapter for Explainable Adaptive IDS.
Detects Npcap / WinPcap drivers and orchestrates Scapy packet capture on Windows hosts.
"""
import os
import platform
import logging
from typing import Dict, Any, List, Callable, Optional

from monitoring.capture.base import BaseCaptureAdapter

logger = logging.getLogger("IDS.Capture.Windows")


class WindowsCaptureAdapter(BaseCaptureAdapter):
    """Windows packet capture adapter using Npcap."""

    def __init__(self):
        self._sniffer = None
        self._is_running = False
        self._active_interface: Optional[str] = None

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """List active Windows network adapters."""
        interfaces: List[Dict[str, Any]] = []
        if platform.system() != "Windows":
            return [
                {"name": "Ethernet", "description": "Windows Ethernet Adapter (Target)", "is_default": True},
                {"name": "Wi-Fi", "description": "Windows Wireless Adapter", "is_default": False}
            ]

        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                name = iface.get("name", "Unknown")
                desc = iface.get("description", "Network Device")
                interfaces.append({
                    "name": name,
                    "description": f"{name} ({desc})",
                    "is_default": ("Ethernet" in name or "Wi-Fi" in name)
                })
        except Exception as exc:
            logger.warning(f"Failed to query Windows interfaces: {exc}")
            interfaces = [{"name": "Ethernet", "description": "Default Network Adapter", "is_default": True}]

        return interfaces

    def check_prerequisites(self) -> Dict[str, Any]:
        """Detect whether Npcap driver is installed on Windows."""
        if platform.system() != "Windows":
            return {
                "has_permission": False,
                "driver_installed": False,
                "diagnostic_note": "Host is not running Windows. Windows adapter cannot be verified locally.",
                "resolution_instructions": "This adapter is compiled for Windows and tested on GitHub Actions runners."
            }

        # Check typical Npcap DLL locations
        sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        npcap_dll = os.path.join(sys32, "Npcap", "wpcap.dll")
        winpcap_dll = os.path.join(sys32, "wpcap.dll")

        driver_installed = os.path.exists(npcap_dll) or os.path.exists(winpcap_dll)

        if driver_installed:
            return {
                "has_permission": True,
                "driver_installed": True,
                "diagnostic_note": "Npcap packet capture driver detected.",
                "resolution_instructions": "Ready for live capture on Windows."
            }
        else:
            return {
                "has_permission": False,
                "driver_installed": False,
                "diagnostic_note": "Npcap capture driver not detected on Windows host.",
                "resolution_instructions": (
                    "Download and install Npcap from https://npcap.com/. "
                    "During installation, ensure 'Install Npcap in WinPcap API-compatible Mode' is checked. "
                    "Alternatively, select Offline Replay Mode."
                )
            }

    def start_capture(self, interface: str, packet_callback: Callable[[Any], None]) -> bool:
        """Start packet capture on Windows."""
        if platform.system() != "Windows":
            logger.error("Cannot start Windows capture adapter on non-Windows host.")
            return False

        prereq = self.check_prerequisites()
        if not prereq["driver_installed"]:
            logger.error(f"Cannot start Windows capture: {prereq['diagnostic_note']}")
            return False

        try:
            from scapy.all import AsyncSniffer
            logger.info(f"Starting Scapy AsyncSniffer on Windows interface '{interface}'...")
            self._sniffer = AsyncSniffer(iface=interface, prn=packet_callback, store=False)
            self._sniffer.start()
            self._is_running = True
            self._active_interface = interface
            return True
        except Exception as exc:
            logger.error(f"Error starting Windows capture: {exc}")
            self._is_running = False
            return False

    def stop_capture(self) -> bool:
        """Stop packet capture cleanly on Windows."""
        if not self._is_running or self._sniffer is None:
            return True

        try:
            self._sniffer.stop()
            self._sniffer = None
            self._is_running = False
            self._active_interface = None
            return True
        except Exception as exc:
            logger.error(f"Error stopping Windows capture: {exc}")
            self._is_running = False
            return False

    @property
    def is_running(self) -> bool:
        return self._is_running
