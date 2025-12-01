from __future__ import annotations

import logging
from collections import deque
from typing import Any, Deque, Dict, Optional, Tuple
from urllib.parse import urljoin

import requests


class SessionManager:
    def __init__(
        self,
        base_url: str,
        *,
        proxies: Optional[Dict[str, str]] = None,
        verify_tls: bool = True,
        default_headers: Optional[Dict[str, str]] = None,
        history_limit: int = 100,
    ) -> None:
        self.base_url = base_url.rstrip('/')
        self.proxies = proxies or {}
        self.verify_tls = verify_tls
        self.default_headers = default_headers or {}
        self._session: Optional[requests.Session] = None
        self._history: Deque[Tuple[str, str, Dict[str, Any], int]] = deque(
            maxlen=history_limit
        )
        self.logger = logging.getLogger(self.__class__.__name__)

    def get_session(self) -> requests.Session:
        if self._session is None:
            session = requests.Session()
            if self.default_headers:
                session.headers.update(self.default_headers)
            if self.proxies:
                session.proxies.update(self.proxies)
            session.verify = self.verify_tls
            self._session = session
            self.logger.debug('Initialized HTTP session for %s', self.base_url)
        return self._session

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None
            self.logger.debug('Closed HTTP session')

    def request(self, method: str, path_or_url: str, **kwargs: Any) -> requests.Response:
        session = self.get_session()
        url = self._build_url(path_or_url)
        response = session.request(method=method, url=url, **kwargs)
        self._record_history(method, url, kwargs, response.status_code)
        self.logger.debug(
            'HTTP %s %s -> %s', method.upper(), url, response.status_code
        )
        return response

    def _build_url(self, path_or_url: str) -> str:
        if path_or_url.startswith('http://') or path_or_url.startswith('https://'):
            return path_or_url
        return urljoin(f'{self.base_url}/', path_or_url.lstrip('/'))

    def _record_history(
        self, method: str, url: str, params: Dict[str, Any], status_code: int
    ) -> None:
        self._history.append((method.upper(), url, params, status_code))

    @property
    def history(self) -> Tuple[Tuple[str, str, Dict[str, Any], int], ...]:
        return tuple(self._history)
