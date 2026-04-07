"""
Hellcat Core Data Models
========================
Central enum / dataclass definitions used by every module.
All other hellcat.* packages import from here.
"""
from __future__ import annotations

import copy
import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DetectorType(Enum):
    INJECTION = "injection"
    AUTH = "auth"
    ACCESS = "access"
    FILE = "file"
    REQUEST = "request"
    MISC = "misc"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ActionType(Enum):
    PORT_SCAN = "port_scan"
    SERVICE_DETECT = "service_detect"
    VULN_SCAN = "vuln_scan"
    WEB_SCAN = "web_scan"
    BRUTE_FORCE = "brute_force"
    EXPLOIT = "exploit"
    PRIVESC = "privesc"
    LATERAL_MOVE = "lateral_move"
    DATA_EXFIL = "data_exfil"
    CREDENTIAL_DUMP = "credential_dump"
    IDENTITY_ATTACK = "identity_attack"
    LOTL = "lotl"
    CLOUD_ABUSE = "cloud_abuse"
    PERSISTENCE = "persistence"
    EVASION = "evasion"


class C2Status(Enum):
    IDLE = "idle"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    RECONNECTING = "reconnecting"
    ERROR = "error"


class TunnelType(Enum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    WEBSOCKET = "websocket"
    ICMP = "icmp"


class LateralStatus(Enum):
    IDLE = "idle"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    EXECUTING = "executing"
    UPLOADING = "uploading"
    DOWNLOADING = "downloading"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    FAILED = "failed"
    ERROR = "error"


class AuthMethod(Enum):
    PASSWORD = "password"
    HASH = "hash"
    TICKET = "ticket"
    KEY = "key"
    CERTIFICATE = "certificate"
    TOKEN = "token"
    AGENT = "agent"


class ExecutionMethod(Enum):
    SMBEXEC = "smbexec"
    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"
    ATEXEC = "atexec"
    DCOMEXEC = "dcomexec"
    WINRM = "winrm"
    SSH = "ssh"


class TargetType(Enum):
    WEB_APPLICATION = "web_application"
    NETWORK_HOST = "network_host"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    BINARY_FILE = "binary_file"
    MOBILE_APP = "mobile_app"
    IOT_DEVICE = "iot_device"
    UNKNOWN = "unknown"


class BeaconMode(Enum):
    INTERACTIVE = "interactive"
    SLEEP = "sleep"
    LOW = "low"


class ToolLevel(Enum):
    SAFE = "safe"
    MODERATE = "moderate"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"


class PersistenceType(Enum):
    REGISTRY = "registry"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    WMI_EVENT = "wmi_event"
    STARTUP_FOLDER = "startup_folder"
    CRONTAB = "crontab"
    SYSTEMD = "systemd"
    LD_PRELOAD = "ld_preload"
    SSH_KEY = "ssh_key"
    SHELL_RC = "shell_rc"
    WEBSHELL = "webshell"


class EvasionLevel(Enum):
    MINIMAL = "minimal"
    MEDIUM = "medium"
    HIGH = "high"
    EXTREME = "extreme"


class PayloadEncoding(Enum):
    NONE = "none"
    BASE64 = "base64"
    XOR = "xor"
    AES = "aes"
    POLYMORPHIC = "polymorphic"


# ---------------------------------------------------------------------------
# Dataclasses - Detection
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """Result from a vulnerability detector."""
    url: str
    vulnerable: bool = False
    vuln_type: str = ""
    severity: Severity = Severity.INFO
    param: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    verified: bool = False
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    request_info: Optional[dict] = None
    response_info: Optional[dict] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vulnerable": self.vulnerable,
            "vuln_type": self.vuln_type,
            "severity": self.severity.value,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence[:500] if self.evidence else "",
            "confidence": self.confidence,
            "verified": self.verified,
            "remediation": self.remediation,
            "references": self.references,
            "extra": self.extra,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Dataclasses - Attack Planning (MCTS)
# ---------------------------------------------------------------------------

@dataclass
class Action:
    """Single attack action for MCTS planner."""
    type: ActionType = ActionType.PORT_SCAN
    name: str = ""
    tool: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.5
    estimated_reward: float = 0.5

    def __hash__(self) -> int:
        return hash((self.type, self.name, self.tool))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Action):
            return NotImplemented
        return self.type == other.type and self.name == other.name and self.tool == other.tool


@dataclass
class AttackState:
    """Represents current penetration test progress for MCTS."""
    target: str = ""
    target_type: str = "unknown"
    open_ports: Dict[int, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    access_level: int = 0
    completed_actions: Set[str] = field(default_factory=set)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def add_open_port(self, port: int, service: str = "unknown") -> None:
        self.open_ports[port] = service

    def add_vulnerability(self, vuln: Dict[str, Any]) -> None:
        self.vulnerabilities.append(vuln)

    def add_credential(self, cred: Dict[str, Any]) -> None:
        self.credentials.append(cred)

    def state_hash(self) -> str:
        raw = f"{self.target}|{sorted(self.open_ports.items())}|{self.access_level}|{sorted(self.completed_actions)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def clone(self) -> AttackState:
        return copy.deepcopy(self)

    def is_terminal(self) -> bool:
        return self.access_level >= 4 or len(self.completed_actions) >= 20

    def reward(self) -> float:
        r = 0.0
        r += len(self.open_ports) * 0.05
        r += len(self.vulnerabilities) * 0.15
        r += len(self.credentials) * 0.25
        r += self.access_level * 0.3
        return min(r, 1.0)


# ---------------------------------------------------------------------------
# Dataclasses - Target Profiling
# ---------------------------------------------------------------------------

@dataclass
class TargetProfile:
    """Comprehensive target intelligence profile."""
    target: str = ""
    target_type: TargetType = TargetType.UNKNOWN
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    cms_type: Optional[str] = None
    cloud_provider: Optional[str] = None
    security_headers: Dict[str, str] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    attack_surface_score: float = 0.0
    risk_level: str = "unknown"
    confidence_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type.value,
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "services": self.services,
            "technologies": self.technologies,
            "cms_type": self.cms_type,
            "cloud_provider": self.cloud_provider,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "attack_surface_score": self.attack_surface_score,
            "risk_level": self.risk_level,
            "confidence_score": self.confidence_score,
        }


@dataclass
class AttackStep:
    """Single step in an attack chain."""
    tool: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_outcome: str = ""
    success_probability: float = 0.0
    execution_time_estimate: int = 60
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """Ordered sequence of attack steps against a target."""
    target_profile: Optional[TargetProfile] = None
    steps: List[AttackStep] = field(default_factory=list)
    total_success_probability: float = 0.0
    estimated_total_time: int = 0
    risk_level: str = "unknown"
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def success_probability(self) -> float:
        if not self.steps:
            return 0.0
        p = 1.0
        for s in self.steps:
            p *= s.success_probability
        return p

    @property
    def estimated_time(self) -> int:
        return sum(s.execution_time_estimate for s in self.steps)

    @property
    def required_tools(self) -> List[str]:
        return list(dict.fromkeys(s.tool for s in self.steps if s.tool))

    def add_step(self, step: AttackStep) -> None:
        self.steps.append(step)
        self.total_success_probability = self.success_probability
        self.estimated_total_time = self.estimated_time

    def calculate_success_probability(self) -> float:
        self.total_success_probability = self.success_probability
        return self.total_success_probability

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target_profile.target if self.target_profile else "",
            "steps": [
                {
                    "tool": s.tool,
                    "parameters": s.parameters,
                    "expected_outcome": s.expected_outcome,
                    "success_probability": s.success_probability,
                    "time_estimate": s.execution_time_estimate,
                }
                for s in self.steps
            ],
            "total_success_probability": self.total_success_probability,
            "estimated_total_time": self.estimated_total_time,
            "risk_level": self.risk_level,
            "created_at": self.created_at,
            "required_tools": self.required_tools,
        }


# ---------------------------------------------------------------------------
# Dataclasses - Credentials & Lateral Movement
# ---------------------------------------------------------------------------

@dataclass
class Credentials:
    """Authentication credentials for lateral movement."""
    username: str = ""
    password: Optional[str] = None
    domain: Optional[str] = None
    ntlm_hash: Optional[str] = None
    aes_key: Optional[str] = None
    ticket: Optional[str] = None
    ssh_key: Optional[str] = None
    ssh_key_data: Optional[str] = None
    ssh_passphrase: Optional[str] = None
    certificate: Optional[str] = None
    method: AuthMethod = AuthMethod.PASSWORD

    def __post_init__(self) -> None:
        if self.ntlm_hash and self.method == AuthMethod.PASSWORD:
            self.method = AuthMethod.HASH
        elif self.ssh_key and self.method == AuthMethod.PASSWORD:
            self.method = AuthMethod.KEY
        elif self.ticket and self.method == AuthMethod.PASSWORD:
            self.method = AuthMethod.TICKET

    @property
    def lm_hash(self) -> str:
        if self.ntlm_hash and ":" in self.ntlm_hash:
            return self.ntlm_hash.split(":")[0]
        return "aad3b435b51404eeaad3b435b51404ee"

    @property
    def nt_hash(self) -> str:
        if self.ntlm_hash and ":" in self.ntlm_hash:
            return self.ntlm_hash.split(":")[1]
        return self.ntlm_hash or ""

    @property
    def full_username(self) -> str:
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "domain": self.domain,
            "method": self.method.value,
            "full_username": self.full_username,
        }


@dataclass
class ExecutionResult:
    """Result from remote command execution."""
    success: bool = False
    output: str = ""
    error: str = ""
    exit_code: int = -1
    duration: float = 0.0
    process_id: Optional[int] = None
    method: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output[:10000] if self.output else "",
            "error": self.error,
            "exit_code": self.exit_code,
            "duration": self.duration,
            "method": self.method,
        }

    def __bool__(self) -> bool:
        return self.success


@dataclass
class FileTransferResult:
    """Result from file upload/download."""
    success: bool = False
    source: str = ""
    destination: str = ""
    size: int = 0
    duration: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "source": self.source,
            "destination": self.destination,
            "size": self.size,
            "duration": self.duration,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Dataclasses - C2 Beacon
# ---------------------------------------------------------------------------

@dataclass
class Task:
    """C2 task to be executed by a beacon."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    type: str = "shell"
    payload: Any = None
    created_at: float = field(default_factory=time.time)
    timeout: float = 300.0
    priority: int = 5

    @classmethod
    def create(cls, task_type: str, payload: Any, timeout: float = 300.0) -> Task:
        return cls(type=task_type, payload=payload, timeout=timeout)


@dataclass
class TaskResult:
    """Result returned by a beacon after executing a task."""
    task_id: str = ""
    success: bool = False
    output: Any = None
    error: Optional[str] = None
    elapsed: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "elapsed": self.elapsed,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TaskResult:
        return cls(
            task_id=data.get("task_id", ""),
            success=data.get("success", False),
            output=data.get("output"),
            error=data.get("error"),
            elapsed=data.get("elapsed", 0.0),
        )


@dataclass
class BeaconInfo:
    """Metadata about a connected beacon."""
    beacon_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    hostname: str = ""
    username: str = ""
    os_info: str = ""
    arch: str = ""
    ip_address: str = ""
    pid: int = 0
    integrity: str = "medium"
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    sleep_time: float = 60.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "beacon_id": self.beacon_id,
            "hostname": self.hostname,
            "username": self.username,
            "os_info": self.os_info,
            "arch": self.arch,
            "ip_address": self.ip_address,
            "pid": self.pid,
            "integrity": self.integrity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sleep_time": self.sleep_time,
        }


# ---------------------------------------------------------------------------
# Dataclasses - CVE Intelligence
# ---------------------------------------------------------------------------

@dataclass
class CVERecord:
    """Single CVE entry in the intelligence database."""
    cve_id: str = ""
    description: str = ""
    cvss_score: float = 0.0
    severity: Severity = Severity.INFO
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    poc_code: Optional[str] = None
    published_date: str = ""
    last_modified: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description[:500],
            "cvss_score": self.cvss_score,
            "severity": self.severity.value,
            "affected_products": self.affected_products,
            "references": self.references,
            "exploit_available": self.exploit_available,
            "published_date": self.published_date,
        }


# ---------------------------------------------------------------------------
# Dataclasses - Scan Configuration
# ---------------------------------------------------------------------------

@dataclass
class ScanConfig:
    """Configuration for a scan session."""
    target: str = ""
    scan_type: str = "full"
    ports: str = ""
    timeout: int = 300
    max_threads: int = 50
    proxy: Optional[str] = None
    verify_ssl: bool = False
    rate_limit_delay: float = 0.3
    wordlist: Optional[str] = None
    auth: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "ports": self.ports,
            "timeout": self.timeout,
            "max_threads": self.max_threads,
            "proxy": self.proxy,
            "verify_ssl": self.verify_ssl,
            "rate_limit_delay": self.rate_limit_delay,
        }


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TaskTypes:
    """Standard C2 task type constants."""
    SHELL = "shell"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    SCREENSHOT = "screenshot"
    KEYLOG = "keylog"
    PERSIST = "persist"
    SLEEP = "sleep"
    EXIT = "exit"
    CHECKIN = "checkin"
    PS = "ps"
    KILL = "kill"
    CD = "cd"
    PWD = "pwd"
    LS = "ls"
    CAT = "cat"
    INJECT = "inject"
    MIGRATE = "migrate"


# Convenience re-exports
__all__ = [
    # Enums
    "Severity", "DetectorType", "RiskLevel", "ActionType",
    "C2Status", "TunnelType", "LateralStatus", "AuthMethod",
    "ExecutionMethod", "TargetType", "BeaconMode", "ToolLevel",
    "PersistenceType", "EvasionLevel", "PayloadEncoding",
    # Dataclasses
    "DetectionResult", "Action", "AttackState",
    "TargetProfile", "AttackStep", "AttackChain",
    "Credentials", "ExecutionResult", "FileTransferResult",
    "Task", "TaskResult", "BeaconInfo",
    "CVERecord", "ScanConfig",
    # Constants
    "TaskTypes",
]
