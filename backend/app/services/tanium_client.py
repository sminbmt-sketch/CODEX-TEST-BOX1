import asyncio
from typing import Any

import httpx

from app.core.config import settings


class TaniumConfigurationError(RuntimeError):
    pass


class TaniumGatewayClient:
    def __init__(self) -> None:
        self.gateway_url = settings.tanium_gateway_url
        self.api_token = settings.tanium_api_token
        self.verify_tls = settings.tanium_verify_tls
        self.timeout = settings.tanium_timeout_seconds

    @property
    def configured(self) -> bool:
        return bool(self.gateway_url and self.api_token)

    @property
    def rest_base_url(self) -> str | None:
        if settings.tanium_base_url is None:
            return None
        return str(settings.tanium_base_url).rstrip("/")

    def _headers(self) -> dict[str, str]:
        if not self.api_token:
            raise TaniumConfigurationError("TANIUM_API_TOKEN is not configured.")
        return {
            "Content-Type": "application/json",
            "session": self.api_token,
        }

    async def execute_read_only(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.gateway_url:
            raise TaniumConfigurationError("TANIUM_BASE_URL is not configured.")
        if "mutation" in query.lower():
            raise ValueError("GraphQL mutations are blocked in Phase 1.")

        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        async with httpx.AsyncClient(verify=self.verify_tls, timeout=self.timeout) as client:
            response = await client.post(self.gateway_url, json=payload, headers=self._headers())
            response.raise_for_status()
            data = response.json()

        if "errors" in data:
            raise RuntimeError(f"Tanium Gateway returned errors: {data['errors']}")
        return data

    async def execute_rest(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        base_url = self.rest_base_url
        if not base_url:
            raise TaniumConfigurationError("TANIUM_BASE_URL is not configured.")
        normalized_path = path if path.startswith("/") else f"/{path}"
        headers = {
            **self._headers(),
            "tanium-options": '{"json_pretty_print":0}',
        }
        async with httpx.AsyncClient(verify=self.verify_tls, timeout=self.timeout) as client:
            response = await client.request(method, f"{base_url}{normalized_path}", json=payload, headers=headers)
            response.raise_for_status()
            return response.json()

    async def ask_rest_question(self, question_text: str, wait_seconds: int = 8) -> dict[str, Any]:
        parsed = await self.execute_rest("POST", "/api/v2/parse_question", {"text": question_text})
        definitions = parsed.get("data") if isinstance(parsed.get("data"), list) else []
        if not definitions:
            raise RuntimeError("Tanium REST parse_question returned no question definitions.")
        created = await self.execute_rest("POST", "/api/v2/questions", definitions[0])
        question = created.get("data") if isinstance(created.get("data"), dict) else created
        question_id = question.get("id") if isinstance(question, dict) else None
        if question_id is None:
            raise RuntimeError("Tanium REST question creation returned no question ID.")
        await asyncio.sleep(wait_seconds)
        return await self.execute_rest("GET", f"/api/v2/result_data/question/{question_id}")

    async def test_connection(self) -> dict[str, Any]:
        return await self.execute_read_only(
            """
            query SecureWatchGatewayTest {
              now
            }
            """
        )

    async def get_endpoint_ids(self, first: int = 50) -> dict[str, Any]:
        first = max(1, min(first, 500))
        return await self.execute_read_only(
            """
            query SecureWatchEndpointIds($first: Int!) {
              endpoints(first: $first) {
                edges {
                  node {
                    id
                  }
                }
              }
            }
            """,
            {"first": first},
        )

    async def get_endpoint_inventory(self, first: int = 50) -> dict[str, Any]:
        first = max(1, min(first, 500))
        return await self.execute_read_only(
            """
            query SecureWatchEndpointInventory($first: Int!) {
              endpoints(first: $first) {
                edges {
                  node {
                    id
                    name
                    ipAddress
                    eidLastSeen
                    os {
                      name
                      generation
                      platform
                    }
                    installedApplications {
                      name
                      version
                      uninstallable
                      silentUninstallString
                    }
                    services {
                      name
                      displayName
                      status
                      startupMode
                    }
                  }
                }
              }
            }
            """,
            {"first": first},
        )

    async def get_endpoint_sensor_readings(self, first: int = 50, sensor_name: str = "Running Processes") -> dict[str, Any]:
        first = max(1, min(first, 500))
        return await self.execute_read_only(
            """
            query SecureWatchEndpointSensorReadings($first: Int!, $sensorName: String!) {
              endpoints(first: $first) {
                edges {
                  node {
                    id
                    sensorReadings(sensors: [{ name: $sensorName }]) {
                      columns {
                        name
                        sensor {
                          name
                        }
                        values
                      }
                    }
                  }
                }
              }
            }
            """,
            {"first": first, "sensorName": sensor_name},
        )

    async def get_endpoint_process_readings(self, first: int = 50, sensor_name: str = "Running Processes") -> dict[str, Any]:
        return await self.get_endpoint_sensor_readings(first=first, sensor_name=sensor_name)
