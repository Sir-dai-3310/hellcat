"""
Hellcat Auth Manager
=====================
Session/Cookie/JWT/OAuth/Bearer token management.
Auto-detect auth type, maintain sessions, refresh tokens.
"""
from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hellcat.auth")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


@dataclass
class AuthProfile:
    name: str = "default"
    auth_type: str = "none"  # none, cookie, bearer, jwt, basic, oauth2
    credentials: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    login_data: Dict[str, str] = field(default_factory=dict)
    token_url: str = ""
    expires_at: float = 0.0

    @property
    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at


class AuthManager:
    """Manage authentication state across scan sessions."""

    def __init__(self) -> None:
        self._profiles: Dict[str, AuthProfile] = {}
        self._active: Optional[str] = None
        self._session = requests.Session()
        self._session.verify = False

    def add_profile(self, profile: AuthProfile) -> None:
        self._profiles[profile.name] = profile
        if self._active is None:
            self._active = profile.name

    def set_active(self, name: str) -> bool:
        if name in self._profiles:
            self._active = name
            return True
        return False

    @property
    def active_profile(self) -> Optional[AuthProfile]:
        return self._profiles.get(self._active or "")

    def get_auth_headers(self) -> Dict[str, str]:
        """Get headers for authenticated requests."""
        p = self.active_profile
        if not p:
            return {}
        headers = dict(p.headers)
        if p.auth_type == "bearer" and p.tokens.get("access_token"):
            headers["Authorization"] = f"Bearer {p.tokens['access_token']}"
        elif p.auth_type == "jwt" and p.tokens.get("jwt"):
            headers["Authorization"] = f"Bearer {p.tokens['jwt']}"
        elif p.auth_type == "basic":
            cred = base64.b64encode(
                f"{p.credentials.get('username','')}:{p.credentials.get('password','')}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {cred}"
        return headers

    def get_auth_cookies(self) -> Dict[str, str]:
        p = self.active_profile
        return dict(p.cookies) if p else {}

    def login(self, profile_name: Optional[str] = None) -> Dict[str, Any]:
        """Perform login and capture session tokens."""
        p = self._profiles.get(profile_name or self._active or "")
        if not p or not p.login_url:
            return {"success": False, "error": "No login URL configured"}
        try:
            resp = self._session.post(
                p.login_url, data=p.login_data,
                headers=p.headers, timeout=15, allow_redirects=True,
            )
            # Capture cookies
            for k, v in resp.cookies.items():
                p.cookies[k] = v
            # Try to extract JWT/token from response
            try:
                body = resp.json()
                for key in ("token", "access_token", "jwt", "session_token", "auth_token"):
                    if key in body:
                        p.tokens[key] = str(body[key])
                        p.auth_type = "bearer" if "access" in key else "jwt"
                if "expires_in" in body:
                    p.expires_at = time.time() + int(body["expires_in"])
            except Exception:
                pass
            # Extract from Set-Cookie
            if resp.cookies and not p.tokens:
                p.auth_type = "cookie"
            return {
                "success": resp.status_code < 400,
                "status_code": resp.status_code,
                "auth_type": p.auth_type,
                "cookies_captured": len(p.cookies),
                "tokens_captured": list(p.tokens.keys()),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def authenticated_request(self, method: str, url: str,
                              **kwargs: Any) -> Dict[str, Any]:
        """Send request with active auth profile applied."""
        p = self.active_profile
        if p and p.is_expired and p.login_url:
            self.login()

        headers = {**kwargs.pop("headers", {}), **self.get_auth_headers()}
        cookies = {**kwargs.pop("cookies", {}), **self.get_auth_cookies()}

        try:
            resp = self._session.request(
                method, url, headers=headers, cookies=cookies,
                timeout=kwargs.pop("timeout", 15), **kwargs,
            )
            return {
                "success": True, "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:10000], "size": len(resp.content),
                "auth_profile": p.name if p else "none",
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    @staticmethod
    def decode_jwt(token: str) -> Dict[str, Any]:
        """Decode JWT payload (no verification)."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}
            payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
            decoded = json.loads(base64.urlsafe_b64decode(payload))
            expired = decoded.get("exp", 0) < time.time() if "exp" in decoded else None
            return {"header": json.loads(base64.urlsafe_b64decode(parts[0] + "==")),
                    "payload": decoded, "expired": expired}
        except Exception as exc:
            return {"error": str(exc)}

    def list_profiles(self) -> List[Dict[str, Any]]:
        return [{"name": p.name, "auth_type": p.auth_type,
                 "active": p.name == self._active,
                 "has_tokens": bool(p.tokens),
                 "has_cookies": bool(p.cookies),
                 "expired": p.is_expired}
                for p in self._profiles.values()]
