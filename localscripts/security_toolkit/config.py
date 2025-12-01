from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass(slots=True)
class LoginConfig:
    endpoint: Optional[str] = None
    username_field: str = 'username'
    password_field: str = 'password'
    extra_fields: Dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ToolkitConfig:
    base_url: Optional[str] = None
    default_headers: Dict[str, str] = field(default_factory=dict)
    verify_tls: bool = True
    proxies: Dict[str, str] = field(default_factory=dict)
    login: LoginConfig = field(default_factory=LoginConfig)
    modules: List[str] = field(default_factory=list)


def load_config(config_path: Optional[Path]) -> ToolkitConfig:
    if not config_path:
        return ToolkitConfig()

    try:
        raw_data = config_path.read_text(encoding='utf-8')
    except FileNotFoundError as exc:
        raise FileNotFoundError(f'Config file not found: {config_path}') from exc

    try:
        data = json.loads(raw_data)
    except json.JSONDecodeError as exc:
        raise ValueError(f'Invalid JSON in config file {config_path}') from exc

    login_data = data.get('login', {})

    return ToolkitConfig(
        base_url=data.get('base_url'),
        default_headers=data.get('default_headers', {}),
        verify_tls=data.get('verify_tls', True),
        proxies=data.get('proxies', {}),
        login=LoginConfig(
            endpoint=login_data.get('endpoint'),
            username_field=login_data.get('username_field', 'username'),
            password_field=login_data.get('password_field', 'password'),
            extra_fields=login_data.get('extra_fields', {}),
        ),
        modules=data.get('modules', []),
    )
