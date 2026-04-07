"""
Hellcat Subdomain Takeover Detector
====================================
Check if CNAME records point to unclaimed services (GitHub Pages,
AWS S3, Heroku, Azure, etc.). Inspired by subzy/can-i-take-over-xyz.
"""
from __future__ import annotations

import logging
import re
import socket
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hellcat.takeover")

# Fingerprints: service -> (cname_pattern, response_signature)
TAKEOVER_FINGERPRINTS: List[Dict[str, Any]] = [
    {"service": "GitHub Pages", "cnames": [".github.io"],
     "fingerprint": "There isn't a GitHub Pages site here"},
    {"service": "Heroku", "cnames": [".herokuapp.com", ".herokudns.com"],
     "fingerprint": "No such app"},
    {"service": "AWS S3", "cnames": [".s3.amazonaws.com", ".s3-website"],
     "fingerprint": "NoSuchBucket"},
    {"service": "Shopify", "cnames": [".myshopify.com"],
     "fingerprint": "Sorry, this shop is currently unavailable"},
    {"service": "Tumblr", "cnames": [".tumblr.com"],
     "fingerprint": "There's nothing here"},
    {"service": "WordPress.com", "cnames": [".wordpress.com"],
     "fingerprint": "Do you want to register"},
    {"service": "Azure", "cnames": [".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net"],
     "fingerprint": "404 Web Site not found"},
    {"service": "Fastly", "cnames": [".fastly.net"],
     "fingerprint": "Fastly error: unknown domain"},
    {"service": "Pantheon", "cnames": [".pantheonsite.io"],
     "fingerprint": "404 error unknown site"},
    {"service": "Surge.sh", "cnames": [".surge.sh"],
     "fingerprint": "project not found"},
    {"service": "Unbounce", "cnames": [".unbouncepages.com"],
     "fingerprint": "The requested URL was not found"},
    {"service": "Ghost", "cnames": [".ghost.io"],
     "fingerprint": "The thing you were looking for is no longer here"},
    {"service": "Netlify", "cnames": [".netlify.app", ".netlify.com"],
     "fingerprint": "Not Found - Request ID"},
    {"service": "Fly.io", "cnames": [".fly.dev"],
     "fingerprint": "404 Not Found"},
    {"service": "Vercel", "cnames": [".vercel.app", ".now.sh"],
     "fingerprint": "DEPLOYMENT_NOT_FOUND"},
]


class SubdomainTakeoverScanner:
    """Check subdomains for takeover vulnerabilities."""

    def __init__(self) -> None:
        self._fingerprints = TAKEOVER_FINGERPRINTS

    def check_single(self, subdomain: str) -> Dict[str, Any]:
        """Check one subdomain for takeover vulnerability."""
        result: Dict[str, Any] = {"subdomain": subdomain, "vulnerable": False,
                                   "cname": "", "service": ""}
        # Resolve CNAME
        cname = self._get_cname(subdomain)
        if not cname:
            result["status"] = "no_cname"
            return result
        result["cname"] = cname

        # Match against fingerprints
        for fp in self._fingerprints:
            if any(pattern in cname.lower() for pattern in fp["cnames"]):
                # Verify by checking HTTP response
                body = self._fetch_body(subdomain)
                if fp["fingerprint"].lower() in body.lower():
                    result["vulnerable"] = True
                    result["service"] = fp["service"]
                    result["evidence"] = fp["fingerprint"]
                    return result
                else:
                    result["service"] = fp["service"]
                    result["status"] = "cname_match_but_claimed"
                    return result

        result["status"] = "no_match"
        return result

    def check_batch(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Check multiple subdomains."""
        return [self.check_single(s) for s in subdomains]

    def check_vulnerable_only(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Return only vulnerable subdomains."""
        return [r for r in self.check_batch(subdomains) if r.get("vulnerable")]

    def _get_cname(self, domain: str) -> str:
        try:
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", domain],
                capture_output=True, text=True, timeout=5,
            )
            cname = result.stdout.strip().rstrip(".")
            return cname
        except Exception:
            try:
                answers = socket.getaddrinfo(domain, None)
                return ""  # Has A record, no CNAME easily extractable
            except Exception:
                return ""

    def _fetch_body(self, domain: str) -> str:
        try:
            import requests
            resp = requests.get(f"http://{domain}", timeout=8, verify=False,
                                allow_redirects=True)
            return resp.text[:5000]
        except Exception:
            return ""

    @staticmethod
    def list_services() -> List[str]:
        return [fp["service"] for fp in TAKEOVER_FINGERPRINTS]
