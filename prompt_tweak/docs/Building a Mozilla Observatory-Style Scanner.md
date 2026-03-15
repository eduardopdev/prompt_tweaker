# Building a Mozilla Observatory-Style Security Scanner in Python

This is a substantial project. Let me walk you through building a comprehensive tool that replicates the Mozilla Observatory methodology.

## Architecture Overview

The Mozilla Observatory checks HTTP response headers and related security configurations, then assigns grades based on a scoring system. Here's how to build it:

## Complete Implementation

### Project Structure
```
observatory_scanner/
├── __init__.py
├── scanner.py          # Main scanner orchestrator
├── checks/
│   ├── __init__.py
│   ├── base.py         # Base check class
│   ├── csp.py          # Content-Security-Policy
│   ├── cookies.py      # Cookie security
│   ├── cors.py         # Cross-Origin Resource Sharing
│   ├── headers.py      # Various security headers
│   ├── hsts.py         # HTTP Strict Transport Security
│   ├── redirection.py  # HTTP -> HTTPS redirection
│   ├── referrer.py     # Referrer-Policy
│   ├── sri.py          # Subresource Integrity
│   ├── xfo.py          # X-Frame-Options
│   ├── xcto.py         # X-Content-Type-Options
│   └── xxss.py         # X-XSS-Protection
├── grader.py           # Score calculation and grading
├── models.py           # Data models
└── cli.py              # Command-line interface
```

### 1. Data Models (`models.py`)

```python
"""Data models for the security scanner."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ScoreModifier(Enum):
    """How a check modifies the score."""
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"


class CheckResult(Enum):
    """Possible outcomes for a check."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"
    NOT_APPLICABLE = "not-applicable"


@dataclass
class TestResult:
    """Result of a single security test."""
    name: str
    title: str
    result: CheckResult
    score_modifier: int  # Points added/subtracted from base score
    description: str
    recommendation: str = ""
    raw_header: Optional[str] = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "result": self.result.value,
            "score_modifier": self.score_modifier,
            "description": self.description,
            "recommendation": self.recommendation,
            "raw_header": self.raw_header,
            "details": self.details,
        }


@dataclass
class ScanResult:
    """Complete scan result for a website."""
    url: str
    final_url: str
    score: int
    grade: str
    tests: list[TestResult] = field(default_factory=list)
    scan_time: float = 0.0
    response_headers: dict = field(default_factory=dict)
    status_code: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "score": self.score,
            "grade": self.grade,
            "scan_time": self.scan_time,
            "status_code": self.status_code,
            "tests": {t.name: t.to_dict() for t in self.tests},
            "errors": self.errors,
        }
```

### 2. Base Check Class (`checks/base.py`)

```python
"""Base class for all security checks."""

from abc import ABC, abstractmethod
from typing import Optional
import requests

from observatory_scanner.models import TestResult


class BaseCheck(ABC):
    """Abstract base class for security checks."""

    def __init__(self):
        self.headers: dict = {}
        self.response: Optional[requests.Response] = None
        self.history: list[requests.Response] = []
        self.url: str = ""
        self.final_url: str = ""
        self.body: str = ""

    def set_context(
        self,
        response: requests.Response,
        history: list[requests.Response],
        url: str,
        final_url: str,
    ):
        """Set the context for the check from the HTTP response."""
        self.response = response
        self.headers = {k.lower(): v for k, v in response.headers.items()}
        self.history = history
        self.url = url
        self.final_url = final_url
        self.body = response.text

    def get_header(self, name: str) -> Optional[str]:
        """Get a header value (case-insensitive)."""
        return self.headers.get(name.lower())

    @abstractmethod
    def check(self) -> TestResult:
        """Run the security check and return a TestResult."""
        pass
```

### 3. Security Checks

#### Content-Security-Policy (`checks/csp.py`)

```python
"""Content-Security-Policy check."""

import re
from observatory_scanner.checks.base import BaseCheck
from observatory_scanner.models import TestResult, CheckResult


class CSPCheck(BaseCheck):
    """
    Checks for Content-Security-Policy header.

    Mozilla Observatory scoring:
    - CSP with default-src 'none' and no unsafe: +10
    - CSP with default-src 'none': +5
    - CSP with default-src but uses unsafe-inline/unsafe-eval: 0
    - CSP header present but no default-src: -10
    - No CSP header: -25
    """

    # Directives that can serve as fallbacks
    FETCH_DIRECTIVES = [
        "child-src", "connect-src", "font-src", "frame-src",
        "img-src", "manifest-src", "media-src", "object-src",
        "script-src", "style-src", "worker-src",
    ]

    UNSAFE_KEYWORDS = ["'unsafe-inline'", "'unsafe-eval'"]

    def _parse_csp(self, csp_string: str) -> dict[str, list[str]]:
        """Parse a CSP header into a dict of directive -> values."""
        policy = {}
        for directive_str in csp_string.split(";"):
            directive_str = directive_str.strip()
            if not directive_str:
                continue
            parts = directive_str.split()
            if parts:
                directive_name = parts[0].lower()
                values = [v.lower() for v in parts[1:]]
                policy[directive_name] = values
        return policy

    def _has_unsafe(self, policy: dict, directive: str) -> bool:
        """Check if a directive uses unsafe-inline or unsafe-eval."""
        values = policy.get(directive, [])
        return any(kw in values for kw in self.UNSAFE_KEYWORDS)

    def _uses_wildcard(self, policy: dict, directive: str) -> bool:
        """Check if a directive uses overly broad sources."""
        values = policy.get(directive, [])
        dangerous = ["*", "http:", "https:", "data:", "blob:"]
        return any(v in dangerous for v in values)

    def check(self) -> TestResult:
        csp = self.get_header("content-security-policy")
        csp_ro = self.get_header("content-security-policy-report-only")

        # No CSP at all
        if not csp:
            if csp_ro:
                return TestResult(
                    name="content-security-policy",
                    title="Content Security Policy",
                    result=CheckResult.INFO,
                    score_modifier=-20,
                    description=(
                        "Content Security Policy (CSP) header is only set in "
                        "report-only mode. This does not enforce any restrictions."
                    ),
                    recommendation=(
                        "Change Content-Security-Policy-Report-Only to "
                        "Content-Security-Policy to enforce the policy."
                    ),
                    raw_header=csp_ro,
                )
            return TestResult(
                name="content-security-policy",
                title="Content Security Policy",
                result=CheckResult.FAIL,
                score_modifier=-25,
                description="Content Security Policy (CSP) header not implemented.",
                recommendation=(
                    "Implement a Content-Security-Policy header. Start with "
                    "a restrictive policy like: default-src 'none'; "
                    "script-src 'self'; style-src 'self'; img-src 'self'; "
                    "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                    "base-uri 'self'; form-action 'self'"
                ),
            )

        policy = self._parse_csp(csp)
        details = {"parsed_policy": {k: v for k, v in policy.items()}}

        # Check for default-src
        has_default_src = "default-src" in policy

        if not has_default_src:
            return TestResult(
                name="content-security-policy",
                title="Content Security Policy",
                result=CheckResult.FAIL,
                score_modifier=-10,
                description=(
                    "CSP header is present but does not contain a default-src directive."
                ),
                recommendation="Add a default-src directive to your CSP.",
                raw_header=csp,
                details=details,
            )

        # Check if default-src is 'none' (most restrictive)
        default_is_none = policy.get("default-src") == ["'none'"]
        default_is_self = "'self'" in policy.get("default-src", [])

        # Check for unsafe-inline and unsafe-eval in script-src and style-src
        script_unsafe = (
            self._has_unsafe(policy, "script-src")
            or (not "script-src" in policy and self._has_unsafe(policy, "default-src"))
        )
        style_unsafe = (
            self._has_unsafe(policy, "style-src")
            or (not "style-src" in policy and self._has_unsafe(policy, "default-src"))
        )

        # Check for wildcards
        has_wildcard = any(
            self._uses_wildcard(policy, d)
            for d in (["default-src"] + self.FETCH_DIRECTIVES)
            if d in policy
        )

        # Check for frame-ancestors (replaces X-Frame-Options)
        has_frame_ancestors = "frame-ancestors" in policy

        # Check for base-uri
        has_base_uri = "base-uri" in policy

        # Check for form-action
        has_form_action = "form-action" in policy

        # Scoring logic (approximating Mozilla Observatory)
        if has_wildcard:
            return TestResult(
                name="content-security-policy",
                title="Content Security Policy",
                result=CheckResult.FAIL,
                score_modifier=-10,
                description=(
                    "CSP uses overly broad source expressions like wildcards, "
                    "http:, https:, data:, or blob:."
                ),
                recommendation="Restrict source expressions to specific origins.",
                raw_header=csp,
                details=details,
            )

        if script_unsafe and style_unsafe:
            return TestResult(
                name="content-security-policy",
                title="Content Security Policy",
                result=CheckResult.WARN,
                score_modifier=-5,
                description=(
                    "CSP is present but uses 'unsafe-inline' or 'unsafe-eval' "
                    "in both script-src and style-src."
                ),
                recommendation=(
                    "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or "
                    "hashes for inline scripts/styles instead."
                ),
                raw_header=csp,
                details=details,
            )

        if script_unsafe:
            return TestResult(
                name="content-security-policy",
                title="Content Security Policy",
                result=CheckResult.WARN,
                score_modifier=-5,
                description=(
                    "CSP is present but uses 'unsafe-inline' or 'unsafe-eval' "
                    "in script-src, which undermines XSS protection."
                ),
                recommendation=(
                    "Remove 'unsafe-inline' and 'unsafe-eval' from script-src. "
                    "Use nonces or hashes instead."
                ),
                raw_header=csp,
                details=details,
            )

        if default_is_none:
            # Best case: default-src 'none' with no unsafe
            bonus = 0
            if has_frame_ancestors:
                bonus += 2
            if has_base_uri:
                bonus += 1
            if has_form_action:
                bonus += 1

            return TestResult(
                name="content-security-policy",
                title="Content Security Policy",
                result=CheckResult.PASS,
                score_modifier=min(10, 5 + bonus),
                description=(
                    "CSP is well-configured with a restrictive default-src 'none' policy."
                ),
                raw_header=csp,
                details=details,
            )

        if default_is_self:
            return TestResult(
                name="content-security-policy",
                title="Content Security Policy",
                result=CheckResult.PASS,
                score_modifier=5,
                description="CSP is implemented with default-src 'self'.",
                raw_header=csp,
                details=details,
            )

        # Has default-src but not 'none' or 'self'
        return TestResult(
            name="content-security-policy",
            title="Content Security Policy",
            result=CheckResult.WARN,
            score_modifier=0,
            description="CSP is present with a default-src directive.",
            raw_header=csp,
            details=details,
        )
```

#### HSTS Check (`checks/hsts.py`)

```python
"""HTTP Strict Transport Security check."""

from observatory_scanner.checks.base import BaseCheck
from observatory_scanner.models import TestResult, CheckResult


class HSTSCheck(BaseCheck):
    """
    Checks for Strict-Transport-Security header.

    Scoring:
    - HSTS with max-age >= 15768000 (6 months) + includeSubDomains + preload: +5
    - HSTS with max-age >= 15768000: 0
    - HSTS with max-age < 15768000: -10
    - No HSTS: -20
    """

    MIN_MAX_AGE = 15768000  # 6 months in seconds
    IDEAL_MAX_AGE = 63072000  # 2 years

    def _parse_hsts(self, header: str) -> dict:
        """Parse HSTS header into components."""
        result = {
            "max_age": None,
            "include_subdomains": False,
            "preload": False,
        }

        for part in header.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age"):
                try:
                    result["max_age"] = int(part.split("=")[1].strip())
                except (ValueError, IndexError):
                    result["max_age"] = None
            elif part == "includesubdomains":
                result["include_subdomains"] = True
            elif part == "preload":
                result["preload"] = True

        return result

    def check(self) -> TestResult:
        # HSTS only makes sense over HTTPS
        if not self.final_url.startswith("https://"):
            return TestResult(
                name="strict-transport-security",
                title="HTTP Strict Transport Security",
                result=CheckResult.FAIL,
                score_modifier=-20,
                description=(
                    "Site does not serve content over HTTPS, so HSTS cannot be set."
                ),
                recommendation="Serve your site over HTTPS and implement HSTS.",
            )

        hsts = self.get_header("strict-transport-security")

        if not hsts:
            return Test