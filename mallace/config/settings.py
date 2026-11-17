"""
Mallace configuration: process environment, explicitly selected runner file, defaults.
Never discover authority from an assessed working directory’s .env.
"""

from __future__ import annotations

from pydantic import Field, model_validator, SecretStr
from datetime import datetime
import ipaddress
import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Administrator-controlled Mallace runner settings."""
    api_access_key: str = Field(default="", repr=False, description="Operator bearer key; empty disables campaign API access")
    approved_target_endpoints: list[str] = Field(default_factory=list, description="Operator-configured exact endpoints permitted for live requests")
    target_approval_expiries: dict[str, datetime] = Field(default_factory=dict, description="UTC approval expiry per exact live endpoint")
    target_auth_tokens: dict[str, SecretStr] = Field(default_factory=dict, repr=False, description="Operator-managed bearer credentials per approved endpoint")
    target_networks: dict[str, list[str]] = Field(default_factory=dict, description="Approved destination CIDRs per exact live endpoint")
    campaign_ledger_path: str = Field(default="mallace.campaigns.db", description="SQLite campaign lifecycle ledger")
    remediation_ledger_path: str | None = Field(default=None,repr=False,description='Explicit absolute existing private remediation ledger for read-only operator status')
    maintenance_registry_path: str | None = Field(default=None,repr=False,description='Explicit private administrator maintenance target registry')
    maintenance_timeout_seconds: int = Field(default=1800,ge=1,le=3600,description='Maximum registered maintenance child runtime')
    max_queued_maintenance_jobs: int = Field(default=20,ge=1,le=100)
    max_concurrent_campaigns: int = Field(default=1, ge=1, le=8, description="Bounded campaigns executing in one local API process")
    max_queued_campaigns: int = Field(default=20, ge=1, le=1000)
    provider_timeout_seconds: float = Field(default=60, ge=1, le=300)
    exploration_timeout_seconds: float = Field(default=120, ge=1, le=600)
    max_target_response_bytes: int = Field(default=65536, ge=1024, le=1048576)
    max_evaluation_characters: int = Field(default=8000, ge=256, le=64000)

    # ── LLM ──────────────────────────────────────────────────────────────
    openai_api_key: str = Field(default="", repr=False, description="OpenAI-compatible provider API key")
    openai_base_url: str = Field(
        default="https://api.openai.com/v1",
        description="Base URL for the OpenAI-compatible proxy",
    )
    primary_model: str = Field(
        default="gpt-4o",
        description="Attack / planning model",
    )
    judge_model: str = Field(
        default="gpt-4o-mini",
        description="Response evaluation model — must differ from primary_model",
    )

    # Provider limits authorize a whole campaign, independently of target-request limits.
    campaign_provider_budget_microdollars: int = Field(default=0,ge=0,le=10000000000,strict=True)
    campaign_max_model_input_tokens: int = Field(default=65536,ge=8193,le=1000000,strict=True)
    campaign_max_model_output_tokens: int = Field(default=2048,ge=1,le=16384,strict=True)
    campaign_model_pricing: list[dict] = Field(default_factory=list,max_length=8,
        description="Explicit administrator model IDs and integer input/output microdollars per million tokens")

    # ── Redis ────────────────────────────────────────────────────────────
    redis_url: str = Field(
        default="redis://localhost:6379",
        repr=False,
        description="Redis connection string for checkpointer + audit log",
    )
    campaign_state_ttl_days: int = Field(
        default=7,
        description="Days to keep campaign state in Redis",
    )

    # ── PostgreSQL ───────────────────────────────────────────────────────
    database_url: str = Field(
        default="postgresql://localhost/red_team",
        repr=False,
        description="PostgreSQL DSN — falls back to SQLite if unreachable",
    )
    sqlite_fallback_path: str = Field(
        default="red_team.db",
        description="SQLite database path used when PostgreSQL is unavailable",
    )

    # ── Safety ───────────────────────────────────────────────────────────
    require_authorization_token: bool = Field(
        default=True,
        description="Enforce campaign authorization tokens",
    )
    max_payload_generations: int = Field(
        default=5,
        ge=0, le=20,
        description="Maximum evolutionary mutation generations per payload",
    )
    execution_rate_limit_ms: int = Field(
        default=500,
        ge=0,
        description="Minimum delay between payload executions (ms)",
    )
    max_campaign_requests: int = Field(default=1000, ge=1, le=100000, description="Maximum target attempts across one campaign's mutation rounds")

    # ── Drift Detection ──────────────────────────────────────────────────
    golden_dataset_min_samples: int = Field(
        default=400,
        ge=1,
        description="Minimum samples required for statistically valid drift testing",
    )
    drift_significance_level: float = Field(
        default=0.05,
        gt=0, lt=1,
        description="p-value threshold for McNemar's test",
    )

    # ── Reporting ────────────────────────────────────────────────────────
    sanitize_poc_payloads: bool = Field(
        default=True,
        description="Redact real attack content in reports",
    )
    generate_sarif: bool = Field(
        default=True,
        description="Produce SARIF 2.1.0 output",
    )
    generate_html: bool = Field(
        default=True,
        description="Produce HTML report",
    )

    # ── AutoGen ──────────────────────────────────────────────────────────
    autogen_max_turns: int = Field(
        default=10,
        ge=1,
        le=20,
        description="Max Attacker ↔ Critic conversation turns",
    )

    # ── Runtime flags ────────────────────────────────────────────────────
    mock_mode: bool = Field(
        default=False,
        description="Run entire pipeline with mock LLM / target (no external deps)",
    )

    model_config = {
        "env_file": None,
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "hide_input_in_errors": True,
    }

    @model_validator(mode="after")
    def validate_judge_separation(self):
        if self.primary_model.strip().casefold() == self.judge_model.strip().casefold():
            raise ValueError("Attack and judge model identifiers must differ")
        if not self.mock_mode and not self.require_authorization_token:
            raise ValueError("Live execution requires campaign authorization")
        if self.maintenance_registry_path is not None and not Path(self.maintenance_registry_path).is_absolute():
            raise ValueError('Maintenance registry requires an absolute path')
        if self.remediation_ledger_path is not None and not Path(self.remediation_ledger_path).is_absolute():
            raise ValueError('Remediation status ledger requires an absolute path')
        for networks in self.target_networks.values():
            for network in networks:
                try:
                    ipaddress.ip_network(network, strict=True)
                except ValueError:
                    raise ValueError("Invalid approved destination network")
        return self


# Module-level singleton — import this everywhere.
_selected_env_file = os.environ.get('MALLACE_ENV_FILE') or None
if _selected_env_file is not None:
    _selected_path = Path(_selected_env_file)
    if not _selected_path.is_absolute() or not _selected_path.is_file() or _selected_path.stat().st_size > 1048576:
        raise ValueError('Explicit runner environment file must be a bounded regular file at an absolute path')
settings = Settings(_env_file=_selected_env_file)
