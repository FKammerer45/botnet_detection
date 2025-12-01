from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


@dataclass(slots=True)
class Evidence:
    name: str
    description: str
    request: Optional[str] = None
    response: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    title: str
    description: str
    severity: Severity
    category: str
    impacted_endpoint: str
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass(slots=True)
class ToolkitContext:
    base_url: str
    session: Any
    config: Any
    run_metadata: Dict[str, Any] = field(default_factory=dict)
