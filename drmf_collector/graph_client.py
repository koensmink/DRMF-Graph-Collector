from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests


GRAPH_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


class GraphClient:
    """Minimal Microsoft Graph REST client with token caching, paging and retry logic."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        graph_base_url: str = "https://graph.microsoft.com/v1.0",
        timeout: int = 30,
        max_retries: int = 4,
    ) -> None:
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.graph_base_url = graph_base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._token: Optional[str] = None
        self._token_expires_epoch: float = 0
        self.session = requests.Session()

    def _get_token(self) -> str:
        now = time.time()
        if self._token and now < self._token_expires_epoch - 120:
            return self._token

        url = GRAPH_TOKEN_URL.format(tenant_id=self.tenant_id)
        data = {
            "client_id": self.client_id,
            "scope": "https://graph.microsoft.com/.default",
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }

        response = self.session.post(url, data=data, timeout=self.timeout)
        response.raise_for_status()

        token_data = response.json()
        self._token = token_data["access_token"]
        self._token_expires_epoch = now + int(token_data.get("expires_in", 3600))
        return self._token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/json",
        }

    def get(self, path_or_url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            url = path_or_url
        else:
            url = f"{self.graph_base_url}/{path_or_url.lstrip('/')}"

        attempt = 0
        while True:
            attempt += 1
            response = self.session.get(
                url,
                headers=self._headers(),
                params=params,
                timeout=self.timeout,
            )

            if response.status_code in (429, 500, 502, 503, 504) and attempt <= self.max_retries:
                retry_after = response.headers.get("Retry-After")
                sleep_seconds = (
                    int(retry_after)
                    if retry_after and retry_after.isdigit()
                    else min(2 ** attempt, 20)
                )
                time.sleep(sleep_seconds)
                continue

            response.raise_for_status()
            return response.json()

    def list_all(self, path_or_url: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        data = self.get(path_or_url, params=params)
        items = list(data.get("value", []))
        next_link = data.get("@odata.nextLink")

        while next_link:
            data = self.get(next_link)
            items.extend(data.get("value", []))
            next_link = data.get("@odata.nextLink")

        return items
