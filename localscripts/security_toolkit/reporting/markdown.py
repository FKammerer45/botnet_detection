from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable

from ..models import Finding, ToolkitContext


class MarkdownReporter:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, context: ToolkitContext, findings: Iterable[Finding]) -> Path:
        findings_list = list(findings)

        timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        report_path = self.output_dir / f'run-{timestamp}.md'

        lines = [
            f"# Security Toolkit Report ({timestamp} UTC)",
            '',
            f"- Target base URL: `{context.base_url}`",
            f"- Total findings: {len(findings_list)}",
            '',
        ]

        if not findings_list:
            lines.append('No findings recorded by the current module set.')
        else:
            for idx, finding in enumerate(findings_list, start=1):
                lines.append(f'## Finding {idx}: {finding.title}')
                lines.append(f'- Severity: **{finding.severity.value.upper()}**')
                lines.append(f'- Category: {finding.category}')
                lines.append(f'- Endpoint: `{finding.impacted_endpoint}`')
                if finding.tags:
                    tag_str = ', '.join(sorted(finding.tags))
                    lines.append(f'- Tags: {tag_str}')
                lines.append('')
                lines.append(f'{finding.description}')
                lines.append('')
                if finding.evidence:
                    lines.append('### Evidence')
                    for evidence in finding.evidence:
                        lines.append(f'- **{evidence.name}**: {evidence.description}')
                        if evidence.request:
                            lines.append('```http')
                            lines.append(evidence.request.strip())
                            lines.append('```')
                        if evidence.response:
                            lines.append('```http')
                            lines.append(evidence.response.strip())
                            lines.append('```')
                        if evidence.metadata:
                            lines.append('Metadata:')
                            for key, value in evidence.metadata.items():
                                lines.append(f'  - {key}: {value}')
                        lines.append('')
                if finding.remediation:
                    lines.append('### Suggested Remediation')
                    lines.append(finding.remediation)
                    lines.append('')

        report_path.write_text('\n'.join(lines), encoding='utf-8')
        return report_path
