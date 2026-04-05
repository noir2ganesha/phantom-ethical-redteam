import logging
import time
import threading

from anthropic import Anthropic
from .base import BaseLLMProvider

logger = logging.getLogger(__name__)


class AnthropicProvider(BaseLLMProvider):
    DEFAULT_MODEL = "claude-sonnet-4-6"

    def __init__(self, api_key: str, model: str = None, oauth_config: dict = None):
        """
        Args:
            api_key: API key or OAuth access token.
            model: Model name override.
            oauth_config: If provided, enables OAuth token refresh.
                Keys:
                    - refresh_token (str): OAuth refresh token.
                    - client_id (str): OAuth client ID.
                    - client_secret (str, optional): OAuth client secret.
                    - token_url (str): Token endpoint URL.
                    - expires_at (float, optional): Unix timestamp when access token expires.
        """
        self._oauth_config = oauth_config
        self._token_lock = threading.Lock()
        self._access_token = api_key

        if oauth_config and oauth_config.get("expires_at"):
            self._token_expires_at = oauth_config["expires_at"]
        else:
            self._token_expires_at = None

        self.client = Anthropic(api_key=self._access_token, timeout=self.TIMEOUT)
        self.model = model or self.DEFAULT_MODEL

    def _is_token_expired(self) -> bool:
        if self._token_expires_at is None:
            return False
        return time.time() >= (self._token_expires_at - 60)  # 60s buffer

    def _refresh_oauth_token(self) -> None:
        """Refresh the OAuth access token using the refresh token."""
        if not self._oauth_config:
            return

        import requests

        cfg = self._oauth_config
        token_url = cfg["token_url"]
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": cfg["refresh_token"],
            "client_id": cfg["client_id"],
        }
        if cfg.get("client_secret"):
            payload["client_secret"] = cfg["client_secret"]

        logger.info("Refreshing OAuth token via %s", token_url)
        resp = requests.post(token_url, data=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        self._access_token = data["access_token"]
        if data.get("refresh_token"):
            self._oauth_config["refresh_token"] = data["refresh_token"]
        if data.get("expires_in"):
            self._token_expires_at = time.time() + data["expires_in"]

        # Recreate client with new token
        self.client = Anthropic(api_key=self._access_token, timeout=self.TIMEOUT)
        logger.info("OAuth token refreshed successfully")

    def _ensure_valid_token(self) -> None:
        """Check and refresh token if expired (thread-safe)."""
        if not self._oauth_config:
            return
        if not self._is_token_expired():
            return
        with self._token_lock:
            # Double-check after acquiring lock
            if self._is_token_expired():
                self._refresh_oauth_token()

    def convert_tools(self, tools: list) -> list:
        return tools  # already in Anthropic format

    def call(self, messages: list, system_prompt: str, tools: list) -> tuple:
        self._ensure_valid_token()

        response = self.client.messages.create(
            model=self.model,
            max_tokens=8192,
            temperature=0.0,
            system=system_prompt,
            messages=messages,
            tools=tools,
            tool_choice={"type": "auto"},
        )

        text_blocks = []
        tool_calls = []

        for content in response.content:
            if content.type == "text":
                text_blocks.append(content.text)
            elif content.type == "tool_use":
                tool_calls.append(
                    {
                        "id": content.id,
                        "name": content.name,
                        "input": content.input,
                    }
                )

        return text_blocks, tool_calls

    def call_with_retry(self, messages: list, system_prompt: str, tools: list) -> tuple:
        """Override to handle OAuth 401 errors with token refresh."""
        last_error = None
        for attempt in range(self.MAX_RETRIES):
            try:
                return self.call(messages, system_prompt, tools)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                last_error = e
                # If 401 and OAuth configured, try refreshing token before retry
                if self._oauth_config and _is_auth_error(e):
                    logger.warning("Auth error detected, refreshing OAuth token")
                    with self._token_lock:
                        self._refresh_oauth_token()
                    continue

                if attempt < self.MAX_RETRIES - 1:
                    wait = self.RETRY_BACKOFF**attempt
                    logger.warning(
                        "LLM API call failed (attempt %d/%d): %s — retrying in %.0fs",
                        attempt + 1,
                        self.MAX_RETRIES,
                        e,
                        wait,
                    )
                    time.sleep(wait)
                else:
                    logger.error(
                        "LLM API call failed after %d attempts: %s",
                        self.MAX_RETRIES,
                        e,
                    )
        raise last_error


def _is_auth_error(exc: Exception) -> bool:
    """Check if an exception is an authentication/authorization error."""
    exc_str = str(exc).lower()
    if "401" in exc_str or "unauthorized" in exc_str or "authentication" in exc_str:
        return True
    # Anthropic SDK raises AuthenticationError
    cls_name = type(exc).__name__.lower()
    return "auth" in cls_name
