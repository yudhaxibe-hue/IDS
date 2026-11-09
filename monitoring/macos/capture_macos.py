"""
macOS Network Capture Adapter for Explainable Adaptive IDS.
Uses Berkeley Packet Filter (BPF) facilities and Scapy AsyncSniffer.
"""
import glob
import os
import platform
import logging
from typing import Dict, Any, List, Callable, Optional
from scapy.all import get_if_list, AsyncSniffer

from monitoring.capture.base import BaseCaptureAdapter

logger = logging.getLogger("IDS.Capture.macOS")


class MacOSCaptureAdapter(BaseCaptureAdapter):
    """macOS packet capture adapter using BPF devices."""

    def __init__(self):
        self._sniffer: Optional[AsyncSniffer] = None
        self._is_running = False
        self._active_interface: Optional[str] = None

    def get_interfaces(self) -> List[Dict[str, Any]]:
        """List active macOS network interfaces."""
        interfaces: List[Dict[str, Any]] = []
        try:
            raw_ifaces = get_if_list()
            for name in raw_ifaces:
                desc = "Loopback Adapter" if name.startswith("lo") else "Network Interface"
                if name.startswith("en0"):
                    desc = "Primary Wi-Fi / Ethernet Adapter"
                interfaces.append({
                    "name": name,
                    "description": f"{name} ({desc})",
                    "is_default": (name == "en0")
                })
        except Exception as exc:
            logger.warning(f"Failed to query network interfaces: {exc}")
            interfaces = [
                {"name": "en0", "description": "Primary Network Adapter", "is_default": True},
                {"name": "lo0", "description": "Loopback Interface", "is_default": False}
            ]
        return interfaces

    def check_prerequisites(self) -> Dict[str, Any]:
        """Verify access to macOS /dev/bpf* capture devices."""
        if platform.system() != "Darwin":
            return {
                "has_permission": False,
                "driver_installed": False,
                "diagnostic_note": "Host is not running macOS.",
                "resolution_instructions": "This adapter is specific to macOS."
            }

        bpf_devices = glob.glob("/dev/bpf*")
        if not bpf_devices:
            return {
                "has_permission": False,
                "driver_installed": False,
                "diagnostic_note": "No BPF capture devices found on macOS host.",
                "resolution_instructions": "Reboot macOS or check system kernel configuration."
            }

        # Check read access on first BPF device
        bpf0 = "/dev/bpf0"
        has_perm = os.access(bpf0, os.R_OK) if os.path.exists(bpf0) else False

        if has_perm:
            return {
                "has_permission": True,
                "driver_installed": True,
                "diagnostic_note": "macOS BPF packet capture permissions are verified.",
                "resolution_instructions": "Ready for live capture."
            }
        else:
            return {
                "has_permission": False,
                "driver_installed": True,
                "diagnostic_note": "Read permission denied on /dev/bpf*. macOS restricts packet capture to privileged users by default.",
                "resolution_instructions": (
                    "To enable live capture without running as root: install the Wireshark ChmodBPF package, "
                    "or run: 'sudo chmod 644 /dev/bpf*' in Terminal. "
                    "Alternatively, select Offline Replay Mode which requires no elevated permissions."
                )
            }

    def start_capture(self, interface: str, packet_callback: Callable[[Any], None]) -> bool:
        """Start Scapy AsyncSniffer on specified network interface."""
        if self._is_running:
            logger.warning("Capture is already running.")
            return True

        prereq = self.check_prerequisites()
        if not prereq["has_permission"]:
            logger.error(f"Cannot start live capture: {prereq['diagnostic_note']}")
            return False

        try:
            logger.info(f"Starting Scapy AsyncSniffer on interface '{interface}'...")
            self._sniffer = AsyncSniffer(
                iface=interface,
                prn=packet_callback,
                store=False  # Do not accumulate packets in RAM
            )
            self._sniffer.start()
            self._is_running = True
            self._active_interface = interface
            logger.info(f"Live packet capture active on '{interface}'.")
            return True
        except Exception as exc:
            logger.error(f"Failed to start live packet capture on {interface}: {exc}")
            self._is_running = False
            return False

    def stop_capture(self) -> bool:
        """Stop AsyncSniffer thread cleanly."""
        if not self._is_running or self._sniffer is None:
            return True

        try:
            logger.info("Stopping macOS packet capture sniffer...")
            self._sniffer.stop()
            self._sniffer = None
            self._is_running = False
            self._active_interface = None
            logger.info("Packet capture stopped cleanly.")
            return True
        except Exception as exc:
            logger.error(f"Error stopping sniffer: {exc}")
            self._is_running = False
            return False

    @property
    def is_running(self) -> bool:
        return self._is_running
