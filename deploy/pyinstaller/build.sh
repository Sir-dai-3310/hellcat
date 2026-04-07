#!/bin/bash
# Hellcat PyInstaller build script
set -e

echo "[*] Building Hellcat single binary..."

pip install pyinstaller 2>/dev/null

pyinstaller \
    --onefile \
    --name hellcat \
    --add-data "hellcat/config:hellcat/config" \
    --add-data "hellcat/payloads:hellcat/payloads" \
    --add-data "hellcat/templates:hellcat/templates" \
    --hidden-import hellcat.core.ai.engine \
    --hidden-import hellcat.core.ai.mcts_planner \
    --hidden-import hellcat.core.detectors.injection.sqli_xss \
    --hidden-import hellcat.core.detectors.auth \
    --hidden-import hellcat.core.c2 \
    --hidden-import hellcat.core.lateral \
    --hidden-import hellcat.core.evasion \
    --hidden-import hellcat.core.persistence \
    --hidden-import hellcat.agents.ctf \
    --hidden-import hellcat.agents.bugbounty \
    --hidden-import hellcat.agents.cve \
    --hidden-import hellcat.agents.identity \
    --hidden-import hellcat.modules.lotl \
    --hidden-import hellcat.modules.payload \
    --hidden-import hellcat.modules.browser \
    --collect-submodules hellcat \
    hellcat/cli.py

echo "[+] Binary built: dist/hellcat"
ls -lh dist/hellcat
