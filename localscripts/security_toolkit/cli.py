from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Iterable, Optional

from .config import ToolkitConfig, load_config
from .http import SessionManager
from .models import ToolkitContext
from .modules import build_checks
from .reporting import MarkdownReporter
from .runner import ToolkitRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='security-toolkit',
        description='Scaffolded helper for web vulnerability triage against HSBC VDP targets.',
    )
    parser.add_argument(
        '--base-url',
        dest='base_url',
        help='Target base URL (overrides value from config file).',
    )
    parser.add_argument(
        '--config',
        dest='config_path',
        type=Path,
        help='Path to JSON configuration file describing authentication flows and defaults.',
    )
    parser.add_argument(
        '--output-dir',
        dest='output_dir',
        type=Path,
        default=Path('security_reports'),
        help='Directory where reports will be written.',
    )
    parser.add_argument(
        '--module',
        dest='modules',
        action='append',
        help='Name of a check to run (repeatable). Defaults to all available checks.',
    )
    parser.add_argument(
        '--proxy',
        dest='proxy',
        help='HTTP/HTTPS proxy to chain requests through (e.g. http://127.0.0.1:8080 for Burp).',
    )
    parser.add_argument(
        '--log-level',
        dest='log_level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Logging verbosity.',
    )
    return parser


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    )


def resolve_base_url(cli_base_url: Optional[str], config: ToolkitConfig) -> str:
    base_url = cli_base_url or config.base_url
    if not base_url:
        raise ValueError('Base URL is required; supply --base-url or set base_url in the config file.')
    return base_url.rstrip('/')


def resolve_proxies(cli_proxy: Optional[str], config: ToolkitConfig) -> Optional[dict[str, str]]:
    if cli_proxy:
        return {'http': cli_proxy, 'https': cli_proxy}
    return config.proxies or None


def select_modules(cli_modules: Optional[Iterable[str]], config: ToolkitConfig) -> Optional[Iterable[str]]:
    if cli_modules:
        return cli_modules
    if config.modules:
        return config.modules
    return None


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_logging(args.log_level)
    logger = logging.getLogger('security_toolkit')

    config = load_config(args.config_path)

    try:
        base_url = resolve_base_url(args.base_url, config)
    except ValueError as exc:
        parser.error(str(exc))

    proxies = resolve_proxies(args.proxy, config)
    checks = build_checks(select_modules(args.modules, config))

    session_manager = SessionManager(
        base_url=base_url,
        proxies=proxies,
        verify_tls=config.verify_tls,
        default_headers=config.default_headers,
    )

    try:
        session = session_manager.get_session()
        context = ToolkitContext(base_url=base_url, session=session, config=config)

        runner = ToolkitRunner(checks)
        logger.warning("Security toolkit modules are currently placeholders; findings may be informational only.")
        findings = runner.run(context)

        reporter = MarkdownReporter(args.output_dir)
        report_path = reporter.generate(context, findings)

        logger.info('Report written to %s', report_path)
    finally:
        session_manager.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
