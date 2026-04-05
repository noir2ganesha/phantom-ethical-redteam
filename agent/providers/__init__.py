import os
from .base import BaseLLMProvider

PROVIDERS = ["anthropic", "openai", "grok", "gemini", "ollama", "mistral", "deepseek", "llamacpp"]


def get_provider(config: dict) -> BaseLLMProvider:
    """
    Factory — imports ONLY the selected provider's module.
    This prevents ImportError when other SDKs are not installed.
    """
    name = config.get("provider", "anthropic").lower()
    model = config.get("model") or None

    if name == "anthropic":
        from .anthropic_provider import AnthropicProvider

        auth_method = config.get("auth_method", "api_key").lower()
        oauth_config = None

        if auth_method == "oauth":
            api_key = (
                os.environ.get("ANTHROPIC_OAUTH_ACCESS_TOKEN")
                or config.get("oauth_access_token", "")
            )
            oauth_config = {
                "refresh_token": (
                    os.environ.get("ANTHROPIC_OAUTH_REFRESH_TOKEN")
                    or config.get("oauth_refresh_token", "")
                ),
                "client_id": (
                    os.environ.get("ANTHROPIC_OAUTH_CLIENT_ID")
                    or config.get("oauth_client_id", "")
                ),
                "client_secret": (
                    os.environ.get("ANTHROPIC_OAUTH_CLIENT_SECRET")
                    or config.get("oauth_client_secret", "")
                ),
                "token_url": config.get(
                    "oauth_token_url", "https://auth.anthropic.com/oauth/token"
                ),
            }
        else:
            api_key = os.environ.get("ANTHROPIC_API_KEY") or config.get("api_key", "")

        return AnthropicProvider(
            api_key=api_key, model=model or "claude-sonnet-4-6", oauth_config=oauth_config
        )

    if name == "openai":
        from .openai_provider import OpenAIProvider

        api_key = os.environ.get("OPENAI_API_KEY") or config.get("api_key", "")
        return OpenAIProvider(api_key=api_key, model=model or "gpt-5.4")

    if name == "grok":
        from .openai_provider import OpenAIProvider

        api_key = os.environ.get("XAI_API_KEY") or config.get("api_key", "")
        return OpenAIProvider(
            api_key=api_key,
            model=model or "grok-4-20-beta",
            base_url=OpenAIProvider.GROK_BASE_URL,
        )

    if name == "gemini":
        from .gemini_provider import GeminiProvider

        api_key = os.environ.get("GEMINI_API_KEY") or config.get("api_key", "")
        return GeminiProvider(api_key=api_key, model=model or "gemini-3.0-pro")

    if name == "ollama":
        from .ollama_provider import OllamaProvider

        host = config.get("ollama_host", "http://localhost:11434")
        timeout = config.get("ollama_timeout")
        return OllamaProvider(
            model=model or "deepseek-v3.2:cloud", host=host, timeout=timeout
        )

    if name == "mistral":
        from .mistral_provider import MistralProvider

        api_key = os.environ.get("MISTRAL_API_KEY") or config.get("api_key", "")
        return MistralProvider(api_key=api_key, model=model or "mistral-large-latest")

    if name == "deepseek":
        from .openai_provider import OpenAIProvider

        api_key = os.environ.get("DEEPSEEK_API_KEY") or config.get("api_key", "")
        return OpenAIProvider(
            api_key=api_key,
            model=model or "deepseek-chat-v3.2",
            base_url=OpenAIProvider.DEEPSEEK_BASE_URL,
        )

    if name == "llamacpp":
        from .openai_provider import OpenAIProvider

        base_url = config.get("llamacpp_base_url", "http://localhost:8080/v1")
        api_key = config.get("api_key") or "no-key"
        return OpenAIProvider(api_key=api_key, model=model or "default", base_url=base_url)

    raise ValueError(f"Unknown provider '{name}'. Choose from: {', '.join(PROVIDERS)}")
