from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..models import Finding, ToolkitContext


class BaseCheck(ABC):
    name: str = 'base_check'
    description: str = ''

    @abstractmethod
    def run(self, context: ToolkitContext) -> List[Finding]:
        raise NotImplementedError
