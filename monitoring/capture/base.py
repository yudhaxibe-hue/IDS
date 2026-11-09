"""
Abstract capture adapter interface for Explainable Adaptive IDS.
Provides common contract for platform-specific capture implementations (macOS BPF / Windows Npcap).
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Callable, Optional


class BaseCaptureAdapter(ABC):
    """Abstract base class defining network capture contract."""

    @abstractmethod
    def get_interfaces(self) -> List[Dict[str, Any]]:
        """List available local network adapters."""
        pass

    @abstractmethod
    def check_prerequisites(self) -> Dict[str, Any]:
        """
        Check OS capture drivers and permissions.
        Returns:
            {
                "has_permission": bool,
                "driver_installed": bool,
                "diagnostic_note": str,
                "resolution_instructions": str
            }
        """
        pass

    @abstractmethod
    def start_capture(self, interface: str, packet_callback: Callable[[Any], None]) -> bool:
        """Start non-blocking packet capture stream on the specified interface."""
        pass

    @abstractmethod
    def stop_capture(self) -> bool:
        """Stop packet capture cleanly and release OS handles."""
        pass

    @property
    @abstractmethod
    def is_running(self) -> bool:
        """Whether capture is currently active."""
        pass
