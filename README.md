# Hellcat

**AI-Driven Autonomous Penetration Testing Framework**

> v1.0.0-alpha · Kali 2026.1 · MCP-native · MIT License

Hellcat fuses MCTS attack-path planning, built-in vulnerability detectors, C2 beacon infrastructure, and external tool orchestration into a single MCP server — purpose-built for Claude Desktop, Cursor, VS Code Copilot, and any MCP-compatible AI client.

---

## Features

| Category | Highlights |
|----------|-----------|
| **Intelligence** | MCTS attack-path planner (UCB1), knowledge graph, multi-model AI engine (OpenAI/Anthropic/Ollama) |
| **Detection** | 19+ built-in detectors — SQLi, XSS, SSRF, SSTI, GraphQL, CORS, DOM XSS, race conditions, auth bypass |
| **Red Team** | C2 beacon (HTTP/DNS/WS/ICMP), lateral movement (SMB/SSH/WMI/WinRM), persistence, LOTL, evasion |
| **Recon** | Subdomain enum, port scanning, service detection, passive/active recon pipelines |
| **Exploitation** | CVE template matching, PoC generation, Nuclei integration, payload mutation framework |
| **Workflows** | CTF solver, Bug Bounty 5-phase pipeline, YAML scan engines (full/quick/web/passive/bounty) |
| **Monitoring** | Continuous scanning, diff detection, Discord/Slack/Telegram webhook alerts |
| **2026 Tactics** | AITM proxies, MFA fatigue chains, cloud IAM enumeration, identity attack chains |

## Architecture

```
┌────────────────────────┐
│  AI Clients (MCP)      │  Claude Desktop · Cursor · VS Code · Windsurf
└──────────┬─────────────┘
           │ stdio (primary)
           ▼
┌────────────────────────┐   ┌──────────────────────┐
│  Hellcat MCP Server    │   │  Flask REST API :8888 │
│  (FastMCP)             │   │  (secondary)          │
│  ┌──────────────────┐  │   │  + Auth middleware     │
│  │ Profile Loader   │  │   │  + Rate limiter        │
│  │ compact/default/ │  │   │  + CORS + Audit log    │
│  │ full/custom      │  │   └──────────────────────┘
│  └──────────────────┘  │
└──────────┬─────────────┘
           │
    ┌──────┴──────┐
    ▼             ▼
┌─────────┐ ┌──────────────┐
│ Built-in│ │ External     │
│ Core    │ │ Tools (64+)  │
│ • MCTS  │ │ nmap, nuclei │
│ • C2    │ │ sqlmap, ffuf │
│ • 19+   │ │ hydra, john  │
│ detect  │ │ ...          │
└─────────┘ └──────────────┘
```

## Quick Start

### 1. Install

```bash
# Clone
git clone https://github.com/Coff0xc/hellcat.git && cd hellcat

# Core install
pip install -e .

# Full install (all optional deps)
pip install -e ".[full]"
```

### 2. Configure AI Client

**Claude Desktop** — copy `config/claude-desktop.json` into `~/.config/Claude/claude_desktop_config.json`

**VS Code** — merge `config/vscode-settings.json` into your VS Code MCP settings

**Cursor** — copy `config/cursor-mcp.json` into `~/.cursor/mcp.json`

**Cherry Studio** — copy `config/cherry-studio-mcp.json` (SSH-based for remote Kali)

### 3. Run

```bash
# MCP server (primary — for AI clients)
hellcat mcp
hellcat mcp --profile compact    # minimal tools for small context windows
hellcat mcp --profile full       # all 120+ tools

# REST API server (secondary — for programmatic access)
hellcat server
hellcat server --host 0.0.0.0 --port 9999

# Quick scan
hellcat scan example.com
hellcat scan 192.168.1.0/24 --quick

# Tool status
hellcat status
hellcat install   # auto-detect missing tools + Kali install command
```

### 4. Docker

```bash
cd deploy/docker
docker compose up -d              # API + Redis + Celery workers
docker compose up -d hellcat-server  # API only
```

## Tool Profiles

Profiles control which MCP tools are loaded, keeping the tool list within AI client context window limits.

| Profile | Categories | Tools | Use Case |
|---------|-----------|-------|----------|
| `compact` | recon, detector | ~20 | Small context windows, quick scans |
| `default` | recon, detector, cve, redteam, bounty | ~60 | General pentesting |
| `full` | all 9 categories | ~120+ | Full red team operations |
| `custom:...` | user-specified | varies | `custom:recon,cve,-bounty` |

```bash
# Set via CLI
hellcat mcp --profile compact

# Set via env
export HELLCAT_PROFILE=full

# List categories
hellcat profile list
```

## API Security

The REST API includes a middleware stack (disabled by default for local use):

```bash
# Enable bearer token auth
export HELLCAT_API_TOKEN=your-secret-token

# All requests must include:
# Authorization: Bearer your-secret-token

# Rate limiting (default: 120 req/min, 20 burst)
export HELLCAT_RATE_LIMIT_RPM=60

# CORS origins
export HELLCAT_CORS_ORIGINS="http://localhost:3000,http://localhost:5173"

# Audit log directory
export HELLCAT_AUDIT_DIR=.hellcat/audit
```

## Run History

All tool executions are logged to `.hellcat/run_history.jsonl`:

```bash
# Browse history
hellcat history
hellcat history --tool nmap --limit 10
hellcat history --status failed
hellcat history --stats

# Export
hellcat history --export results.json
```

## Error Recovery

Hellcat implements 3-tier automatic recovery for tool failures:

1. **Retry** — Exponential backoff for transient errors (timeouts, connection resets)
2. **Fallback** — Automatic tool substitution (nmap → rustscan → masscan)
3. **Escalate** — Human notification when all recovery exhausted

## YAML Scan Engines

Define custom scan pipelines:

```yaml
# Built-in engines: full_scan, quick_scan, web_audit, bug_bounty, passive_recon
phases:
  - name: recon
    tools:
      - tool: nmap
        args: ["-sV", "-T4", "-p-", "{target}"]
        timeout: 600
  - name: detect
    detectors: [sqli, xss, ssrf, ssti, cors, dom_xss]
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HELLCAT_HOST` | `127.0.0.1` | API bind address |
| `HELLCAT_PORT` | `8888` | API port |
| `HELLCAT_DEBUG` | `0` | Debug mode |
| `HELLCAT_PROFILE` | `default` | MCP tool profile |
| `HELLCAT_API_TOKEN` | *(none)* | Bearer token (empty = auth disabled) |
| `HELLCAT_RATE_LIMIT_RPM` | `120` | Requests per minute per IP |
| `HELLCAT_CORS_ORIGINS` | `http://localhost:*` | Allowed CORS origins |
| `HELLCAT_DATA_DIR` | `.hellcat` | Data directory |
| `HELLCAT_AUDIT_DIR` | `.hellcat/audit` | Audit log directory |
| `OPENAI_API_KEY` | *(none)* | OpenAI API key |
| `ANTHROPIC_API_KEY` | *(none)* | Anthropic API key |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |

## Project Structure

```
hellcat/
├── cli.py                  # CLI (click)
├── hellcat_mcp.py          # MCP stdio server (FastMCP)
├── hellcat_server.py        # Flask REST API
├── __init__.py
├── api/
│   ├── middleware/          # Auth, rate limiting, CORS, audit
│   └── routes/             # Blueprint modules (14 categories)
├── agents/                 # Hierarchical agent architecture
├── config/                 # MCP client configs, PoC index, wordlists
├── core/
│   ├── ai/                 # Intelligence, MCTS planner, AI engine
│   ├── c2/                 # C2 beacon + tunnels
│   ├── cache/              # LRU cache
│   ├── container.py        # IoC dependency injection
│   ├── detectors/          # 19+ vulnerability detectors
│   ├── engine.py           # YAML scan engine
│   ├── evasion/            # AMSI/WAF bypass
│   ├── knowledge/          # Knowledge graph
│   ├── lateral/            # SMB/SSH/WMI/WinRM
│   ├── models.py           # Central dataclasses + enums
│   ├── monitor.py          # Continuous monitoring + webhooks
│   ├── orchestrator.py     # Multi-agent orchestrator
│   ├── persistence/        # Registry/cron/webshell
│   ├── profiles.py         # Tool profile management
│   ├── reasoning.py        # Task tree + dependency resolution
│   ├── recovery.py         # 3-tier error recovery
│   ├── run_history.py      # Persistent run history
│   ├── security/           # AuthManager, InputValidator, ScopeValidator
│   └── tools/              # External tool manager (64+ tools)
├── deploy/
│   ├── docker/             # Dockerfile + docker-compose.yml
│   ├── debian/             # .deb packaging
│   └── pyinstaller/        # Binary bundling
├── handlers/               # MCP tool registration (9 categories)
├── modules/                # Shared modules
├── payloads/               # SQLi/XSS/LFI/RCE/SSTI/XXE/CMD/WAF payloads
├── templates/              # Report templates
└── tests/                  # pytest suite
```

## Requirements

- Python 3.10+
- Kali Linux 2026.1 (recommended) or any Linux with security tools installed

## License

MIT — Coff0xc
