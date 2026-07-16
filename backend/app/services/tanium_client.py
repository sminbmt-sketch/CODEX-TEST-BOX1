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

    async def get_endpoint_process_readings(self, first: int = 50, sensor_name: str = "Running Processes") -> dict[str, Any]:
        first = max(1, min(first, 500))
        return await self.execute_read_only(
            """
            query SecureWatchEndpointProcessReadings($first: Int!, $sensorName: String!) {
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

    async def get_endpoint_sbom_findings(self, first: int = 50) -> dict[str, Any]:
        first = max(1, min(first, 500))
        return await self.execute_read_only(
            """
            query SecureWatchEndpointSbomFindings($first: Int!) {
              endpoints(first: $first) {
                edges {
                  node {
                    id
                    compliance {
                      cveFindings {
                        cveId
                        detectedProducts
                        cpes
                        severity
                        severityV3
                        cvssScore
                        cvssScoreV3
                        scanType
                        firstFound
                        lastFound
                        remediation
                      }
                    }
                  }
                }
              }
            }
            """,
            {"first": first},
        )
