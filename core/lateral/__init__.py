"""
Hellcat Lateral Movement Framework
===================================
Abstract base + concrete modules for SMB/SSH/WMI/WinRM/PsExec lateral movement.
Ported from AutoRedTeam-Orchestrator core/lateral/.
"""
from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union

from hellcat.core.models import (
    AuthMethod, Credentials, ExecutionResult, FileTransferResult, LateralStatus,
)

logger = logging.getLogger("hellcat.lateral")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

class LateralConfig:
    def __init__(self, **kw: Any) -> None:
        self.timeout: float = kw.get("timeout", 30.0)
        self.port: Optional[int] = kw.get("port")
        self.retry_count: int = kw.get("retry_count", 3)
        self.retry_delay: float = kw.get("retry_delay", 1.0)
        self.smb_port: int = kw.get("smb_port", 445)
        self.smb_share: str = kw.get("smb_share", "ADMIN$")
        self.ssh_port: int = kw.get("ssh_port", 22)
        self.wmi_namespace: str = kw.get("wmi_namespace", "root/cimv2")
        self.winrm_port: int = kw.get("winrm_port", 5985)
        self.winrm_use_ssl: bool = kw.get("winrm_use_ssl", False)


# ---------------------------------------------------------------------------
# Base module
# ---------------------------------------------------------------------------

class BaseLateralModule(ABC):
    name: str = "base"
    description: str = ""
    default_port: int = 0
    supported_auth: List[AuthMethod] = [AuthMethod.PASSWORD]
    supports_file_transfer: bool = False

    def __init__(self, target: str, credentials: Credentials,
                 config: Optional[LateralConfig] = None) -> None:
        self.target = target
        self.credentials = credentials
        self.config = config or LateralConfig()
        self.status = LateralStatus.IDLE
        self._connect_time: Optional[float] = None
        self._last_activity: float = time.time()

    @property
    def port(self) -> int:
        return self.config.port or self.default_port

    @property
    def is_connected(self) -> bool:
        return self.status in (LateralStatus.CONNECTED, LateralStatus.AUTHENTICATED)

    def _set_status(self, s: LateralStatus) -> None:
        self.status = s
        self._last_activity = time.time()

    @abstractmethod
    def connect(self) -> bool: ...

    @abstractmethod
    def disconnect(self) -> None: ...

    @abstractmethod
    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult: ...

    def upload(self, local_path: str, remote_path: str) -> FileTransferResult:
        return FileTransferResult(success=False, error="Upload not supported")

    def download(self, remote_path: str, local_path: str) -> FileTransferResult:
        return FileTransferResult(success=False, error="Download not supported")

    def test_connection(self) -> bool:
        try:
            r = self.execute("echo hellcat_probe")
            return r.success and "hellcat_probe" in r.output
        except Exception:
            return False

    def get_info(self) -> Dict[str, Any]:
        return {"module": self.name, "target": self.target, "port": self.port,
                "status": self.status.value, "auth_method": self.credentials.method.value}

    def __enter__(self) -> BaseLateralModule:
        self.connect()
        return self

    def __exit__(self, *_: Any) -> None:
        self.disconnect()


# ---------------------------------------------------------------------------
# SSH Module
# ---------------------------------------------------------------------------

class SSHModule(BaseLateralModule):
    name = "ssh"
    description = "SSH remote execution via Paramiko"
    default_port = 22
    supported_auth = [AuthMethod.PASSWORD, AuthMethod.KEY]
    supports_file_transfer = True

    def __init__(self, target: str, credentials: Credentials,
                 config: Optional[LateralConfig] = None) -> None:
        super().__init__(target, credentials, config)
        self._client: Any = None

    def connect(self) -> bool:
        self._set_status(LateralStatus.CONNECTING)
        try:
            import paramiko
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kw: Dict[str, Any] = {
                "hostname": self.target, "port": self.port,
                "username": self.credentials.username,
                "timeout": self.config.timeout,
            }
            if self.credentials.method == AuthMethod.KEY and self.credentials.ssh_key:
                kw["key_filename"] = self.credentials.ssh_key
            elif self.credentials.password:
                kw["password"] = self.credentials.password
            self._client.connect(**kw)
            self._set_status(LateralStatus.AUTHENTICATED)
            self._connect_time = time.time()
            return True
        except Exception as exc:
            self._set_status(LateralStatus.FAILED)
            logger.error("SSH connect failed %s: %s", self.target, exc)
            return False

    def disconnect(self) -> None:
        if self._client:
            self._client.close()
        self._set_status(LateralStatus.DISCONNECTED)

    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        if not self._client:
            return ExecutionResult(success=False, error="Not connected")
        self._set_status(LateralStatus.EXECUTING)
        start = time.time()
        try:
            _, stdout, stderr = self._client.exec_command(command, timeout=timeout or self.config.timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            code = stdout.channel.recv_exit_status()
            self._set_status(LateralStatus.AUTHENTICATED)
            return ExecutionResult(success=code == 0, output=out, error=err,
                                   exit_code=code, duration=time.time() - start, method="ssh")
        except Exception as exc:
            self._set_status(LateralStatus.ERROR)
            return ExecutionResult(success=False, error=str(exc), duration=time.time() - start, method="ssh")

    def upload(self, local_path: str, remote_path: str) -> FileTransferResult:
        if not self._client:
            return FileTransferResult(success=False, error="Not connected")
        start = time.time()
        try:
            sftp = self._client.open_sftp()
            sftp.put(local_path, remote_path)
            stat = sftp.stat(remote_path)
            sftp.close()
            return FileTransferResult(success=True, source=local_path, destination=remote_path,
                                      size=stat.st_size, duration=time.time() - start)
        except Exception as exc:
            return FileTransferResult(success=False, error=str(exc), duration=time.time() - start)


# ---------------------------------------------------------------------------
# SMB Module (Pass-the-Hash via impacket)
# ---------------------------------------------------------------------------

class SMBModule(BaseLateralModule):
    name = "smb"
    description = "SMB remote execution via Impacket (smbexec)"
    default_port = 445
    supported_auth = [AuthMethod.PASSWORD, AuthMethod.HASH]

    def connect(self) -> bool:
        self._set_status(LateralStatus.CONNECTING)
        try:
            from impacket.smbconnection import SMBConnection
            self._conn = SMBConnection(self.target, self.target, sess_port=self.port)
            if self.credentials.method == AuthMethod.HASH:
                self._conn.login(self.credentials.username, "",
                                 domain=self.credentials.domain or "",
                                 lmhash=self.credentials.lm_hash,
                                 nthash=self.credentials.nt_hash)
            else:
                self._conn.login(self.credentials.username,
                                 self.credentials.password or "",
                                 domain=self.credentials.domain or "")
            self._set_status(LateralStatus.AUTHENTICATED)
            return True
        except Exception as exc:
            self._set_status(LateralStatus.FAILED)
            logger.error("SMB connect failed %s: %s", self.target, exc)
            return False

    def disconnect(self) -> None:
        if hasattr(self, "_conn") and self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
        self._set_status(LateralStatus.DISCONNECTED)

    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        self._set_status(LateralStatus.EXECUTING)
        start = time.time()
        try:
            from impacket.smbexec import SMBEXEC
            executer = SMBEXEC(
                command, username=self.credentials.username,
                password=self.credentials.password or "",
                domain=self.credentials.domain or "",
                hashes=self.credentials.ntlm_hash,
                share=self.config.smb_share,
            )
            output = executer.run(self.target, self.port)
            self._set_status(LateralStatus.AUTHENTICATED)
            return ExecutionResult(success=True, output=str(output),
                                   duration=time.time() - start, method="smbexec")
        except Exception as exc:
            self._set_status(LateralStatus.ERROR)
            return ExecutionResult(success=False, error=str(exc),
                                   duration=time.time() - start, method="smbexec")


# ---------------------------------------------------------------------------
# Auto-selector
# ---------------------------------------------------------------------------

def auto_lateral(target: str, credentials: Credentials,
                 config: Optional[LateralConfig] = None) -> Optional[BaseLateralModule]:
    """Auto-select the best lateral movement module based on credentials and target."""
    if credentials.method == AuthMethod.KEY or credentials.ssh_key:
        return SSHModule(target, credentials, config)
    if credentials.method == AuthMethod.HASH or credentials.ntlm_hash:
        return SMBModule(target, credentials, config)
    # Default: try SSH first (more universal)
    return SSHModule(target, credentials, config)
