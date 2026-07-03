from fastapi.testclient import TestClient

from app.main import app


def main() -> None:
    with TestClient(app) as client:
        health = client.get("/health")
        summary = client.get("/api/dashboard/summary")
        tanium = client.get("/api/tanium/status")

    print({"health": health.status_code, "summary": summary.status_code, "tanium": tanium.status_code})
    health.raise_for_status()
    summary.raise_for_status()
    tanium.raise_for_status()


if __name__ == "__main__":
    main()
