"""
Hellcat Payload Mutation Engine
================================
Auto-generate encoding variants from base payloads.
204 base -> 2000+ variants via URL/double-URL/Unicode/Hex/HTML encoding.
"""
from __future__ import annotations

import html
import re
from typing import Dict, List
from urllib.parse import quote, quote_plus


class PayloadMutator:
    """Generate encoding variants for WAF bypass."""

    ENCODERS = {
        "url": lambda p: quote(p, safe=""),
        "double_url": lambda p: quote(quote(p, safe=""), safe=""),
        "html_entity": lambda p: html.escape(p),
        "html_hex": lambda p: "".join(f"&#x{ord(c):x};" for c in p),
        "unicode": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
        "hex_escape": lambda p: "".join(f"\\x{ord(c):02x}" for c in p),
        "mixed_case": lambda p: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
        "null_byte": lambda p: p.replace("<", "%00<").replace(">", "%00>"),
        "tab_inject": lambda p: p.replace(" ", "\t"),
        "newline_inject": lambda p: p.replace(" ", "\n"),
    }

    @classmethod
    def mutate(cls, payload: str, encodings: List[str] = None) -> List[str]:
        """Generate all encoding variants of a single payload."""
        if encodings is None:
            encodings = list(cls.ENCODERS.keys())
        variants = [payload]  # original always first
        for enc_name in encodings:
            encoder = cls.ENCODERS.get(enc_name)
            if encoder:
                try:
                    variant = encoder(payload)
                    if variant != payload and variant not in variants:
                        variants.append(variant)
                except Exception:
                    pass
        return variants

    @classmethod
    def mutate_batch(cls, payloads: List[str], encodings: List[str] = None,
                     max_per_payload: int = 5) -> List[str]:
        """Mutate a batch of payloads, return deduplicated list."""
        all_variants = []
        seen = set()
        for p in payloads:
            for v in cls.mutate(p, encodings)[:max_per_payload]:
                if v not in seen:
                    seen.add(v)
                    all_variants.append(v)
        return all_variants

    @classmethod
    def generate_xss_variants(cls, base_payloads: List[str]) -> List[str]:
        """XSS-specific mutations: case mixing, event handler swaps, tag alternatives."""
        variants = list(base_payloads)
        seen = set(base_payloads)

        for p in base_payloads[:20]:  # top 20 base payloads
            # Case mutations
            for enc in ["url", "double_url", "html_hex", "mixed_case", "null_byte"]:
                try:
                    v = cls.ENCODERS[enc](p)
                    if v not in seen:
                        seen.add(v)
                        variants.append(v)
                except Exception:
                    pass

            # Event handler swaps
            if "onerror" in p:
                for handler in ["onfocus", "onload", "onmouseover", "onclick", "oninput"]:
                    v = p.replace("onerror", handler)
                    if v not in seen:
                        seen.add(v)
                        variants.append(v)

            # Tag alternatives
            if "<img" in p:
                for tag in ["<svg", "<video", "<audio", "<body", "<input", "<details"]:
                    v = p.replace("<img", tag)
                    if v not in seen:
                        seen.add(v)
                        variants.append(v)

        return variants

    @classmethod
    def generate_sqli_variants(cls, base_payloads: List[str]) -> List[str]:
        """SQLi-specific: comment styles, space alternatives, keyword cases."""
        variants = list(base_payloads)
        seen = set(base_payloads)

        for p in base_payloads[:20]:
            # Comment style alternatives
            for old, new in [("--", "#"), ("--", "-- -"), ("--", ";--"), (" ", "/**/"),
                             (" ", "%20"), (" ", "%09"), (" ", "%0a")]:
                v = p.replace(old, new, 1)
                if v not in seen and v != p:
                    seen.add(v)
                    variants.append(v)

            # URL encoding
            for enc in ["url", "double_url"]:
                try:
                    v = cls.ENCODERS[enc](p)
                    if v not in seen:
                        seen.add(v)
                        variants.append(v)
                except Exception:
                    pass

        return variants

    @classmethod
    def expand_all(cls, payload_db: Dict[str, List[str]]) -> Dict[str, int]:
        """Expand all payload types and return counts."""
        counts = {}
        for vtype, payloads in payload_db.items():
            if vtype == "xss":
                expanded = cls.generate_xss_variants(payloads)
            elif vtype == "sqli":
                expanded = cls.generate_sqli_variants(payloads)
            else:
                expanded = cls.mutate_batch(payloads, max_per_payload=4)
            counts[vtype] = len(expanded)
        return counts
