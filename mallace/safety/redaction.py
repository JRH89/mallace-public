"""Literal known-credential redaction; not a general sensitive-data detector."""
from mallace.config.settings import settings


def redact_known_credentials(text: str, *extra_values: str | None) -> str:
    values = {settings.api_access_key, settings.openai_api_key,
              *(value for value in extra_values if value),
              *(token.get_secret_value() for token in settings.target_auth_tokens.values())}
    for value in sorted(values, key=len, reverse=True):
        if value:
            text = text.replace(value, '[REDACTED]')
    return text


def redact_structure(value):
    if isinstance(value, str):
        return redact_known_credentials(value)
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_structure(item) for key, item in value.items()}
    return value


def redact_publication_credentials(text: str, *extra_values: str | None) -> str:
    """Supported credential shapes for publication/model context; not comprehensive DLP."""
    import re
    text=redact_known_credentials(text,*extra_values)
    text=re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)','[REDACTED PRIVATE KEY]',text,flags=re.S)
    text=re.sub(r'\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bAKIA[A-Z0-9]{16}\b|\bsk-[A-Za-z0-9_-]{24,}', '[REDACTED CREDENTIAL]',text)
    return text
