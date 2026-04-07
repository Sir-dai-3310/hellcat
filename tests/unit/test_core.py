"""Hellcat core unit tests — validates all major modules."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

def test_models():
    from hellcat.core.models import AttackState, Action, ActionType, Credentials, Task, DetectionResult, Severity
    s = AttackState(target="10.0.0.1")
    s.add_open_port(80, "http")
    assert s.open_ports[80] == "http"
    assert len(s.state_hash()) == 16
    c = s.clone()
    c.add_open_port(22, "ssh")
    assert 22 not in s.open_ports  # deep copy
    a = Action(type=ActionType.EXPLOIT, name="test", tool="sqlmap")
    assert hash(a) == hash(Action(type=ActionType.EXPLOIT, name="test", tool="sqlmap"))
    cr = Credentials(username="admin", ntlm_hash="aad3b435:8846f7ea")
    assert cr.method.value == "hash"
    t = Task.create("shell", "whoami")
    assert len(t.id) > 0
    dr = DetectionResult(url="http://x", vulnerable=True, severity=Severity.HIGH)
    assert dr.to_dict()["severity"] == "high"

def test_container():
    from hellcat.core.container import Container, Lifetime
    c = Container()
    class Svc:
        def __init__(self): self.x = 42
    c.register_singleton(Svc)
    assert c.resolve(Svc) is c.resolve(Svc)
    assert c.resolve(Svc).x == 42
    c.register_instance(str, "hello")
    assert c.resolve(str) == "hello"

def test_detectors():
    from hellcat.core.detectors import DetectorFactory, BaseDetector, CompositeDetector, register_detector
    from hellcat.core.models import Severity, DetectorType
    DetectorFactory.clear()
    @register_detector("test_det")
    class T(BaseDetector):
        name="t"; severity=Severity.LOW; detector_type=DetectorType.MISC
        def detect(self, url, **kw): return [self._create_result(url, confidence=0.5)]
    assert DetectorFactory.exists("test_det")
    r = DetectorFactory.create("test_det").detect("http://x")
    assert r[0].vulnerable and r[0].confidence == 0.5
    comp = CompositeDetector([DetectorFactory.create("test_det")])
    assert len(comp.detect("http://x")) == 1
    DetectorFactory.clear()

def test_mcts():
    from hellcat.core.ai.mcts_planner import MCTSPlanner
    from hellcat.core.models import AttackState
    s = AttackState(target="10.0.0.1")
    s.add_open_port(80, "http")
    p = MCTSPlanner(seed=42).plan(s, iterations=50)
    assert p["root_visits"] == 50
    assert len(p["recommended_actions"]) >= 1

def test_knowledge():
    from hellcat.core.knowledge import KnowledgeManager
    km = KnowledgeManager()
    t = km.store_target("10.0.0.1")
    v = km.store_vulnerability(t, "CVE-2026-1", "critical")
    assert km.stats()["total_entities"] == 2
    assert km.stats()["total_relationships"] == 1
    km.clear()

def test_c2():
    from hellcat.core.c2 import Beacon, BeaconConfig
    from hellcat.core.models import Task, TaskTypes
    b = Beacon(BeaconConfig(server="127.0.0.1"))
    r = b.process_task(Task.create(TaskTypes.PWD, None))
    assert r.success

def test_evasion():
    from hellcat.core.evasion import EvasionEngine
    from hellcat.core.models import EvasionLevel
    e = EvasionEngine()
    enc = e.encode_payload(b"test", EvasionLevel.HIGH)
    assert enc != b"test"
    assert e.get_amsi_bypass() is not None
    assert len(e.get_injection_techniques()) >= 3

def test_persistence():
    from hellcat.core.persistence import PersistenceGenerator, PersistenceType
    from hellcat.core.models import EvasionLevel
    w = PersistenceGenerator.generate_windows(PersistenceType.REGISTRY, "evil.exe")
    assert "install" in w
    l = PersistenceGenerator.generate_linux(PersistenceType.CRONTAB, "/tmp/x")
    assert "crontab" in l["install"]
    ws = PersistenceGenerator.generate_webshell("php_basic", EvasionLevel.HIGH)
    assert ws["filename"].endswith(".php")

def test_tools():
    from hellcat.core.tools import ExternalToolManager
    mgr = ExternalToolManager()
    assert mgr.status_report()["total_registered"] >= 30

def test_security():
    from hellcat.core.security import AuthManager, InputValidator, ScopeValidator
    from hellcat.core.models import ToolLevel
    a = AuthManager(max_level=ToolLevel.MODERATE)
    assert a.is_allowed("nmap") and not a.is_allowed("hydra")
    assert InputValidator.is_private_ip("192.168.1.1")
    s = ScopeValidator()
    s.add_scope("example.com")
    assert s.is_in_scope("test.example.com") and not s.is_in_scope("evil.com")

def test_lotl():
    from hellcat.modules.lotl import LOTLManager
    assert LOTLManager.stats()["total_techniques"] >= 15
    assert len(LOTLManager.get_by_detection_risk(0.4)) >= 3

def test_payloads():
    from hellcat.modules.payload import PayloadGenerator
    assert len(PayloadGenerator.get_payloads("xss")) >= 3
    assert sum(PayloadGenerator.count_all().values()) >= 50

def test_cve_templates():
    from hellcat.core.cve import CVETemplateManager
    assert len(CVETemplateManager.list_all()) == 5
    m = CVETemplateManager.match_target({"open_ports": [23], "banners": ["GNU inetutils"]})
    assert len(m) >= 1

def test_identity():
    from hellcat.agents.identity import IdentityAttackManager
    assert set(IdentityAttackManager.list_chains()) == {"aitm", "mfa_fatigue", "cloud_iam"}

def test_ctf():
    from hellcat.agents.ctf import CTFWorkflowManager
    assert CTFWorkflowManager.suggest_category("buffer overflow") == "pwn"
    assert len(CTFWorkflowManager.list_categories()) == 7

def test_bugbounty():
    from hellcat.agents.bugbounty import BugBountyWorkflowManager, BugBountyTarget
    wf = BugBountyWorkflowManager.create_workflow(BugBountyTarget(domain="x.com"))
    assert wf["total_phases"] == 5

def test_cache():
    from hellcat.core.cache import AdvancedCache, TokenBucketRateLimiter, CircuitBreaker
    c = AdvancedCache(max_size=10)
    c.set("k", "v", ttl=60)
    assert c.get("k") == "v"
    assert c.get("miss") is None
    assert c.hit_rate > 0
    rl = TokenBucketRateLimiter(rate=100, burst=10)
    assert rl.allow()
    cb = CircuitBreaker(failure_threshold=2)
    assert cb.state == "closed"

def test_report():
    from hellcat.core.session import ReportGenerator
    rg = ReportGenerator()
    rg.set_metadata(target="example.com")
    rg.add_finding({"vuln_type": "XSS", "severity": "high", "url": "http://x", "confidence": 0.9})
    md = rg.to_markdown()
    assert "XSS" in md and "example.com" in md
    html = rg.to_html()
    assert "<h1>" in html
    j = rg.to_json()
    assert "example.com" in j

# === v1.1+ NEW MODULE TESTS ===

def test_repeater_intruder():
    from hellcat.modules.web_scanner import Repeater, Intruder, HTTPRequest
    rep = Repeater(timeout=5)
    # Intruder cluster bomb (offline, no network)
    intr = Intruder(rep)
    req = HTTPRequest(method="GET", url="http://test", params={"a": "1", "b": "2"})
    # Test cluster_bomb generates correct number of combos
    combos = intr.cluster_bomb(req, {"a": ["x", "y"], "b": ["1", "2"]})
    # Can't send real requests but structure should be correct
    assert len(combos) == 4
    # Pitchfork
    pairs = intr.pitchfork(req, {"a": ["x", "y"], "b": ["1", "2"]})
    assert len(pairs) == 2

def test_auth_manager():
    from hellcat.modules.api_security import AuthManager, AuthProfile
    am = AuthManager()
    am.add_profile(AuthProfile(name="t1", auth_type="bearer", tokens={"access_token": "abc"}))
    assert am.get_auth_headers()["Authorization"] == "Bearer abc"
    am.add_profile(AuthProfile(name="t2", auth_type="basic",
                               credentials={"username": "u", "password": "p"}))
    am.set_active("t2")
    h = am.get_auth_headers()
    assert h["Authorization"].startswith("Basic ")
    jwt_data = AuthManager.decode_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.x")
    assert jwt_data.get("payload", {}).get("sub") == "1234567890"

def test_ssrf_detector():
    from hellcat.core.detectors import DetectorFactory
    try:
        from hellcat.core.detectors.request import SSRFDetector
    except Exception:
        pass
    assert DetectorFactory.exists("ssrf")
    assert DetectorFactory.exists("race_condition")
    assert DetectorFactory.exists("graphql")

def test_dom_xss():
    from hellcat.core.detectors.injection.dom_xss import DOMXSSDetector
    det = DOMXSSDetector()
    html = '<script>document.getElementById("x").innerHTML = location.hash;</script>'
    results = det.detect("http://test", page_source=html)
    assert len(results) >= 1

def test_bounty_report():
    from hellcat.templates.report import BountyReportGenerator
    finding = {"vuln_type": "sqli", "url": "http://t.com/s", "param": "q",
               "payload": "' OR 1=1--", "evidence": "error", "severity": "critical"}
    r = BountyReportGenerator.generate(finding)
    assert r["severity"] == "critical"
    assert "$5,000" in r["estimated_bounty"]
    md = BountyReportGenerator.generate_markdown(finding)
    assert "Steps to Reproduce" in md

def test_scan_engine():
    from hellcat.core.engine import ScanEngine
    eng = ScanEngine()
    engines = eng.list_engines()
    assert len(engines) >= 5
    names = [e["id"] for e in engines]
    assert "full_scan" in names and "quick_scan" in names and "bug_bounty" in names

def test_monitor():
    from hellcat.core.monitor import DiffDetector, ScanSnapshot
    old = ScanSnapshot(open_ports=[22, 80])
    new = ScanSnapshot(open_ports=[22, 80, 443], subdomains=["new.test.com"])
    old.compute_fingerprint(); new.compute_fingerprint()
    diff = DiffDetector.diff(old, new)
    assert diff["changed"]
    assert 443 in diff["new_ports"]
    assert "new.test.com" in diff["new_subdomains"]

def test_orchestrator():
    from hellcat.core.orchestrator import Orchestrator
    orch = Orchestrator()
    pipeline = orch.create_pipeline("10.0.0.1", "quick")
    assert len(pipeline) == 5
    roles = [t.role.value for t in pipeline]
    assert "recon" in roles and "reporter" in roles

def test_reasoning():
    from hellcat.core.reasoning import ReasoningModule, ResultParser
    rm = ReasoningModule()
    summary = rm.initialize("10.0.0.1")
    assert summary["total"] >= 8
    action = rm.get_next_action()
    assert action is not None and action["tool"] == "nmap"
    # Parser
    p = ResultParser.parse_nmap("22/tcp open ssh OpenSSH 10.2\n80/tcp open http Apache")
    assert p["ports"] == [22, 80]
    p2 = ResultParser.parse_nuclei("[CVE-X] [http] [critical] http://t.com")
    assert len(p2["vulns"]) == 1

def test_payload_mutator():
    from hellcat.modules.payload.mutator import PayloadMutator
    variants = PayloadMutator.mutate("<script>alert(1)</script>")
    assert len(variants) >= 5
    xss_exp = PayloadMutator.generate_xss_variants(["<img src=x onerror=alert(1)>"])
    assert len(xss_exp) >= 3

def test_tunnels():
    from hellcat.core.c2.tunnels import DNSTunnel, HTTPSTunnel
    from hellcat.core.c2 import C2Config
    dns = DNSTunnel(C2Config(domain="test.com"))
    assert dns.connect()
    dns.disconnect()

def test_lateral_windows():
    from hellcat.core.lateral.windows import WMIModule, WinRMModule
    # Import only, no real connection
    assert WMIModule.name == "wmi"
    assert WinRMModule.name == "winrm"

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"  PASS {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"\n{'='*40}\n{passed} passed, {failed} failed out of {len(tests)}")
