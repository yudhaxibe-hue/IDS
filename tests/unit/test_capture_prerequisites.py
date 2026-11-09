"""
Unit tests for platform capture prerequisite checks and user guidance.
"""
import pytest
import platform
from monitoring.macos.capture_macos import MacOSCaptureAdapter
from monitoring.windows.capture_windows import WindowsCaptureAdapter


def test_macos_adapter_prerequisites():
    """Verify macOS adapter checks BPF devices and returns diagnostic guidance."""
    adapter = MacOSCaptureAdapter()
    prereqs = adapter.check_prerequisites()

    assert "has_permission" in prereqs
    assert "driver_installed" in prereqs
    assert "diagnostic_note" in prereqs
    assert "resolution_instructions" in prereqs

    if platform.system() == "Darwin":
        assert isinstance(prereqs["has_permission"], bool)
        assert len(prereqs["resolution_instructions"]) > 0


def test_windows_adapter_prerequisites():
    """Verify Windows adapter returns Npcap guidance."""
    adapter = WindowsCaptureAdapter()
    prereqs = adapter.check_prerequisites()

    assert "has_permission" in prereqs
    assert "driver_installed" in prereqs
    assert "diagnostic_note" in prereqs
    assert "resolution_instructions" in prereqs
    assert "Npcap" in prereqs["resolution_instructions"] or "Windows" in prereqs["diagnostic_note"]


def test_interfaces_listing():
    """Verify available interface discovery."""
    mac_adapter = MacOSCaptureAdapter()
    ifaces = mac_adapter.get_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    assert "name" in ifaces[0]
