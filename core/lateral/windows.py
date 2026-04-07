"""
Hellcat WMI/WinRM Lateral Movement
===================================
Concrete implementations using impacket (WMI) and pywinrm (WinRM).
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

from hellcat.core.lateral import BaseLateralModule, LateralConfig
from hellcat.core.models import AuthMethod, Credentials, ExecutionResult, LateralStatus

logger = logging.getLogger("hellcat.lateral.win")


class WMIModule(BaseLateralModule):
    name = "wmi"
    description = "WMI remote execution via impacket wmiexec"
    default_port = 135
    supported_auth = [AuthMethod.PASSWORD, AuthMethod.HASH]

    def connect(self) -> bool:
        self._set_status(LateralStatus.CONNECTING)
        try:
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            self._dcom = DCOMConnection(
                self.target, self.credentials.username,
                self.credentials.password or "",
                self.credentials.domain or "",
                self.credentials.lm_hash, self.credentials.nt_hash,
            )
            self._set_status(LateralStatus.AUTHENTICATED)
            return True
        except ImportError:
            logger.error("impacket not installed")
            self._set_status(LateralStatus.FAILED)
            return False
        except Exception as exc:
            logger.error("WMI connect failed %s: %s", self.target, exc)
            self._set_status(LateralStatus.FAILED)
            return False

    def disconnect(self) -> None:
        if hasattr(self, "_dcom") and self._dcom:
            try:
                self._dcom.disconnect()
            except Exception:
                pass
        self._set_status(LateralStatus.DISCONNECTED)

    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        self._set_status(LateralStatus.EXECUTING)
        start = time.time()
        try:
            from impacket.dcerpc.v5.dcom.wmi import WBEMCLASS
            iWbemServices = self._dcom.CoCreateInstanceEx(
                "{F5F3B3B1-4B13-11D2-A89D-00C04FB16F9E}", "//./root/cimv2")
            output = ""
            # Simplified: use Win32_Process.Create
            win32Process, _ = iWbemServices.GetObject("Win32_Process")
            win32Process.Create(command, "C:\\", None)
            self._set_status(LateralStatus.AUTHENTICATED)
            return ExecutionResult(success=True, output="Command dispatched (async)",
                                   duration=time.time() - start, method="wmi")
        except Exception as exc:
            self._set_status(LateralStatus.ERROR)
            return ExecutionResult(success=False, error=str(exc),
                                   duration=time.time() - start, method="wmi")


class WinRMModule(BaseLateralModule):
    name = "winrm"
    description = "WinRM remote execution via pywinrm"
    default_port = 5985
    supported_auth = [AuthMethod.PASSWORD]

    def __init__(self, target: str, credentials: Credentials,
                 config: Optional[LateralConfig] = None) -> None:
        super().__init__(target, credentials, config)
        self._session: Any = None

    def connect(self) -> bool:
        self._set_status(LateralStatus.CONNECTING)
        try:
            import winrm
            port = self.config.winrm_port
            scheme = "https" if self.config.winrm_use_ssl else "http"
            self._session = winrm.Session(
                f"{scheme}://{self.target}:{port}",
                auth=(self.credentials.full_username, self.credentials.password or ""),
                transport="ntlm",
                server_cert_validation="ignore",
            )
            # Test connection
            result = self._session.run_cmd("echo hellcat_probe")
            if b"hellcat_probe" in result.std_out:
                self._set_status(LateralStatus.AUTHENTICATED)
                return True
            self._set_status(LateralStatus.FAILED)
            return False
        except ImportError:
            logger.error("pywinrm not installed: pip install pywinrm")
            self._set_status(LateralStatus.FAILED)
            return False
        except Exception as exc:
            logger.error("WinRM connect failed %s: %s", self.target, exc)
            self._set_status(LateralStatus.FAILED)
            return False

    def disconnect(self) -> None:
        self._session = None
        self._set_status(LateralStatus.DISCONNECTED)

    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        if not self._session:
            return ExecutionResult(success=False, error="Not connected")
        self._set_status(LateralStatus.EXECUTING)
        start = time.time()
        try:
            result = self._session.run_cmd(command)
            out = result.std_out.decode(errors="replace")
            err = result.std_err.decode(errors="replace")
            self._set_status(LateralStatus.AUTHENTICATED)
            return ExecutionResult(success=result.status_code == 0, output=out, error=err,
                                   exit_code=result.status_code, duration=time.time() - start,
                                   method="winrm")
        except Exception as exc:
            self._set_status(LateralStatus.ERROR)
            return ExecutionResult(success=False, error=str(exc),
                                   duration=time.time() - start, method="winrm")

    def execute_ps(self, script: str) -> ExecutionResult:
        """Execute PowerShell script via WinRM."""
        if not self._session:
            return ExecutionResult(success=False, error="Not connected")
        start = time.time()
        try:
            result = self._session.run_ps(script)
            return ExecutionResult(
                success=result.status_code == 0,
                output=result.std_out.decode(errors="replace"),
                error=result.std_err.decode(errors="replace"),
                exit_code=result.status_code, duration=time.time() - start,
                method="winrm_ps",
            )
        except Exception as exc:
            return ExecutionResult(success=False, error=str(exc), method="winrm_ps")
