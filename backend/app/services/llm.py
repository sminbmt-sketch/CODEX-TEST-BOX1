import httpx

from app.core.config import settings


class SummaryService:
    async def summarize(self, title: str, body: str, source_urls: list[str]) -> str | None:
        if settings.llm_provider == "disabled":
            return None

        payload = {
            "model": settings.llm_model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You summarize security issues in Korean. Use only the provided text. "
                        "Mention uncertainty. Do not invent affected products or CVEs."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Title: {title}\n\nBody:\n{body[:8000]}\n\nSources:\n" + "\n".join(source_urls),
                },
            ],
            "temperature": 0.2,
        }
        headers = {"Content-Type": "application/json"}
        if settings.llm_api_key:
            headers["Authorization"] = f"Bearer {settings.llm_api_key}"

        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
