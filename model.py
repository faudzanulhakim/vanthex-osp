"""
Pentest Toolkit — typed core models (model.py, v3.14).

dataclasses + enum + typing for the toolkit's core records. The legacy
engine (vulnscan2.F) speaks plain dicts; this module is the typed boundary
for NEW code (canary, CLI, future modules): Finding round-trips losslessly
to/from the F() dict shape so both worlds interoperate.
"""
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    CLEAN = "CLEAN"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    CANDIDATE = "candidate"


class Origin(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO]


@dataclass
class Finding:
    severity: Severity
    title: str
    description: str = ""
    evidence: str = ""
    cwe: str = ""
    owasp: str = ""
    cvss: float = 0.0
    remediation: str = ""
    confidence: Confidence = Confidence.PROBABLE
    location: str = ""
    param: str = ""
    origin: Origin = Origin.ACTIVE

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["origin"] = self.origin.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        known = {f for f in cls.__dataclass_fields__}
        kw = {k: v for k, v in (d or {}).items() if k in known}
        try:
            kw["severity"] = Severity(str(kw.get("severity", "INFO")).upper())
        except ValueError:
            kw["severity"] = Severity.INFO
        try:
            kw["confidence"] = Confidence(str(kw.get("confidence", "probable")).lower())
        except ValueError:
            kw["confidence"] = Confidence.PROBABLE
        try:
            kw["origin"] = Origin(str(kw.get("origin", "active")).lower())
        except ValueError:
            kw["origin"] = Origin.ACTIVE
        kw["cvss"] = float(kw.get("cvss") or 0.0)
        return cls(**kw)


def overall_risk(findings: List[Dict[str, Any]]) -> str:
    sevs = {str(f.get("severity", "")).upper() for f in findings}
    for sev in _SEV_ORDER:
        if sev.value in sevs:
            return sev.value
    return Severity.CLEAN.value
