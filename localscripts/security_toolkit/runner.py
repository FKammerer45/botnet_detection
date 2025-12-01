from __future__ import annotations

import logging
from typing import Iterable, List

from .models import Finding, ToolkitContext
from .modules.base import BaseCheck


class ToolkitRunner:
    def __init__(self, checks: Iterable[BaseCheck]) -> None:
        self.checks = list(checks)
        self.logger = logging.getLogger(self.__class__.__name__)

    def run(self, context: ToolkitContext) -> List[Finding]:
        findings: List[Finding] = []
        for check in self.checks:
            self.logger.info('Running check: %s', check.name)
            try:
                check_findings = check.run(context)
                if check_findings:
                    findings.extend(check_findings)
                    self.logger.info(
                        'Check %s produced %d findings',
                        check.name,
                        len(check_findings),
                    )
                else:
                    self.logger.info('Check %s reported no findings', check.name)
            except Exception as exc:
                self.logger.exception('Check %s failed: %s', check.name, exc)
        return findings
