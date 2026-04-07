"""
Hellcat Browser Automation Agent
=================================
Headless Chrome via Selenium (+ optional Playwright fallback).
Page navigation, DOM analysis, form detection, security header analysis,
cookie inspection, active XSS testing.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hellcat.browser")


class BrowserAgent:
    """AI-powered browser agent for web application testing."""

    def __init__(self) -> None:
        self._driver: Any = None

    def setup(self, headless: bool = True) -> bool:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            opts = Options()
            if headless:
                opts.add_argument("--headless=new")
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--ignore-certificate-errors")
            self._driver = webdriver.Chrome(options=opts)
            self._driver.set_page_load_timeout(30)
            return True
        except Exception as exc:
            logger.warning("Browser setup failed: %s", exc)
            return False

    def navigate_and_inspect(self, url: str, wait: int = 3) -> Dict[str, Any]:
        if not self._driver:
            if not self.setup():
                return {"success": False, "error": "Browser unavailable"}
        try:
            self._driver.get(url)
            import time
            time.sleep(wait)
            page_source = self._driver.page_source
            return {
                "success": True,
                "url": self._driver.current_url,
                "title": self._driver.title,
                "page_length": len(page_source),
                "forms": self._extract_forms(),
                "links": self._extract_links()[:50],
                "cookies": self._get_cookies(),
                "security_headers": self._analyze_headers(),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _extract_forms(self) -> List[Dict[str, Any]]:
        try:
            from selenium.webdriver.common.by import By
            forms = self._driver.find_elements(By.TAG_NAME, "form")
            result = []
            for f in forms[:20]:
                inputs = f.find_elements(By.TAG_NAME, "input")
                result.append({
                    "action": f.get_attribute("action") or "",
                    "method": f.get_attribute("method") or "get",
                    "inputs": [{"name": i.get_attribute("name"), "type": i.get_attribute("type")}
                               for i in inputs[:10]],
                })
            return result
        except Exception:
            return []

    def _extract_links(self) -> List[str]:
        try:
            from selenium.webdriver.common.by import By
            anchors = self._driver.find_elements(By.TAG_NAME, "a")
            return [a.get_attribute("href") for a in anchors if a.get_attribute("href")]
        except Exception:
            return []

    def _get_cookies(self) -> List[Dict[str, Any]]:
        try:
            cookies = self._driver.get_cookies()
            return [{
                "name": c["name"], "domain": c.get("domain", ""),
                "secure": c.get("secure", False), "httpOnly": c.get("httpOnly", False),
                "sameSite": c.get("sameSite", ""),
            } for c in cookies]
        except Exception:
            return []

    def _analyze_headers(self) -> Dict[str, Any]:
        """Check for security headers via JavaScript fetch."""
        try:
            script = """
            return fetch(window.location.href).then(r => {
                let h = {}; r.headers.forEach((v,k) => h[k]=v); return h;
            });
            """
            headers = self._driver.execute_async_script(
                "var cb=arguments[arguments.length-1];" + script.replace("return ", "").replace(";", ".then(cb);")
            )
            if not headers:
                return {}
            security_checks = {
                "csp": "content-security-policy" in headers,
                "hsts": "strict-transport-security" in headers,
                "x_frame": "x-frame-options" in headers,
                "x_content_type": "x-content-type-options" in headers,
                "referrer_policy": "referrer-policy" in headers,
            }
            return {"headers": headers, "security_checks": security_checks}
        except Exception:
            return {}

    def screenshot(self, output_path: str = "screenshot.png") -> bool:
        try:
            self._driver.save_screenshot(output_path)
            return True
        except Exception:
            return False

    def close(self) -> None:
        if self._driver:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None

    def __del__(self) -> None:
        self.close()
