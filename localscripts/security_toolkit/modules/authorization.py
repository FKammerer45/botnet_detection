from __future__ import annotations

import logging
from typing import List

from ..models import Finding, Severity, ToolkitContext
from .base import BaseCheck


class AuthorizationSweepCheck(BaseCheck):
    name = 'authorization_sweep'
    description = (
        'Prototype scaffold for authorization/IDOR probing. Replace placeholder logic '
        'with HSBC-specific request replay and response validation.'
    )

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)

    def run(self, context: ToolkitContext) -> List[Finding]:
        self.logger.debug(
            'Authorization sweep placeholder executed against %s', context.base_url
        )
        return [
            Finding(
                title='Authorization sweep stub',
                description=(
                    'Replace this placeholder with concrete authorization testing logic. '
                    'Use the session in the toolkit context to replay authenticated '
                    'requests with mutated identifiers and compare responses.'
                ),
                severity=Severity.INFO,
                category='authorization',
                impacted_endpoint=context.base_url,
                tags=['placeholder'],
            )
        ]
