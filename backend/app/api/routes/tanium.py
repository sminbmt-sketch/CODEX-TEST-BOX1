from fastapi import APIRouter, HTTPException, Query

from app.services.tanium_client import TaniumConfigurationError, TaniumGatewayClient
from app.schemas import TaniumStatus

router = APIRouter(prefix="/tanium", tags=["tanium"])


@router.get("/status", response_model=TaniumStatus)
def status() -> TaniumStatus:
    client = TaniumGatewayClient()
    if client.configured:
        return TaniumStatus(configured=True, gateway_url=client.gateway_url, message="Tanium Gateway is configured.")
    return TaniumStatus(configured=False, gateway_url=client.gateway_url, message="Tanium URL or API token is missing.")


@router.post("/test")
async def test_connection() -> dict:
    client = TaniumGatewayClient()
    try:
        return await client.test_connection()
    except TaniumConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Tanium Gateway test failed: {exc}") from exc


@router.get("/endpoints")
async def endpoint_ids(first: int = Query(default=50, ge=1, le=500)) -> dict:
    client = TaniumGatewayClient()
    try:
        return await client.get_endpoint_ids(first=first)
    except TaniumConfigurationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Tanium endpoint query failed: {exc}") from exc
