from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import requests


ARM_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


class ArmClient:
    """
    Minimal Azure Resource Manager client.

    Uses the same Entra app registration as the Graph collector, but requests an ARM token:
    https://management.azure.com/.default
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        arm_base_url: str = "https://management.azure.com",
        timeout: int = 30,
        max_retries: int = 4,
    ) -> None:
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.arm_base_url = arm_base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self._token: Optional[str] = None
        self._token_expires_epoch: float = 0
        self.session = requests.Session()

    @classmethod
    def from_env(cls) -> "ArmClient":
        tenant_id = os.getenv("TENANT_ID")
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")

        missing = [
            name
            for name, value in {
                "TENANT_ID": tenant_id,
                "CLIENT_ID": client_id,
                "CLIENT_SECRET": client_secret,
            }.items()
            if not value
        ]
        if missing:
            raise ValueError(f"Missing required environment variables for ARM client: {', '.join(missing)}")

        return cls(
            tenant_id=str(tenant_id),
            client_id=str(client_id),
            client_secret=str(client_secret),
            arm_base_url=os.getenv("ARM_BASE_URL", "https://management.azure.com"),
        )

    def _get_token(self) -> str:
        now = time.time()
        if self._token and now < self._token_expires_epoch - 120:
            return self._token

        response = self.session.post(
            ARM_TOKEN_URL.format(tenant_id=self.tenant_id),
            data={
                "client_id": self.client_id,
                "scope": "https://management.azure.com/.default",
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
            },
            timeout=self.timeout,
        )
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

    def get(
        self,
        path_or_url: str,
        params: Optional[Dict[str, Any]] = None,
        api_version: Optional[str] = None,
    ) -> Dict[str, Any]:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            url = path_or_url
        else:
            url = f"{self.arm_base_url}/{path_or_url.lstrip('/')}"

        request_params = dict(params or {})
        if api_version and "api-version" not in request_params:
            request_params["api-version"] = api_version

        attempt = 0
        while True:
            attempt += 1
            response = self.session.get(
                url,
                headers=self._headers(),
                params=request_params,
                timeout=self.timeout,
            )

            if response.status_code in (429, 500, 502, 503, 504) and attempt <= self.max_retries:
                retry_after = response.headers.get("Retry-After")
                sleep_seconds = int(retry_after) if retry_after and retry_after.isdigit() else min(2 ** attempt, 20)
                time.sleep(sleep_seconds)
                continue

            response.raise_for_status()
            return response.json()

    def list_all(
        self,
        path_or_url: str,
        params: Optional[Dict[str, Any]] = None,
        api_version: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        data = self.get(path_or_url, params=params, api_version=api_version)
        items = list(data.get("value", []))

        next_link = data.get("nextLink")
        while next_link:
            data = self.get(next_link)
            items.extend(data.get("value", []))
            next_link = data.get("nextLink")

        return items

    def list_subscription_ids(self) -> List[str]:
        configured = os.getenv("AZURE_SUBSCRIPTION_IDS", "").strip()
        if configured:
            return [item.strip() for item in configured.split(",") if item.strip()]

        subscriptions = self.list_all("/subscriptions", api_version="2020-01-01")
        return [
            subscription["subscriptionId"]
            for subscription in subscriptions
            if subscription.get("subscriptionId")
        ]

    def list_resources(
        self,
        subscription_id: str,
        filter_expression: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if filter_expression:
            params["$filter"] = filter_expression

        return self.list_all(
            f"/subscriptions/{subscription_id}/resources",
            params=params,
            api_version="2021-04-01",
        )

    def list_resources_by_type(self, subscription_id: str, resource_type: str) -> List[Dict[str, Any]]:
        return self.list_resources(
            subscription_id=subscription_id,
            filter_expression=f"resourceType eq '{resource_type}'",
        )

    def get_resource_by_id(self, resource_id: str, api_version: str) -> Dict[str, Any]:
        return self.get(resource_id, api_version=api_version)

    def list_diagnostic_settings(self, resource_id: str) -> List[Dict[str, Any]]:
        return self.list_all(
            f"{resource_id.rstrip('/')}/providers/Microsoft.Insights/diagnosticSettings",
            api_version="2021-05-01-preview",
        )
