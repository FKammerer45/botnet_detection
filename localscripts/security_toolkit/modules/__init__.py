from __future__ import annotations

from collections import OrderedDict
from typing import Iterable, List, Optional

from .authorization import AuthorizationSweepCheck
from .base import BaseCheck


AVAILABLE_CHECKS = OrderedDict(
    (check.name, check)
    for check in [
        AuthorizationSweepCheck,
    ]
)


def build_checks(selected: Optional[Iterable[str]] = None) -> List[BaseCheck]:
    if not selected:
        return [cls() for cls in AVAILABLE_CHECKS.values()]

    checks: List[BaseCheck] = []
    for name in selected:
        cls = AVAILABLE_CHECKS.get(name)
        if cls is None:
            raise ValueError(f'Unknown check requested: {name}')
        checks.append(cls())
    return checks


__all__ = ['build_checks', 'AVAILABLE_CHECKS', 'BaseCheck']
