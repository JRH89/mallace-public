"""Immutable trusted policy and bounded evidence schemas; neither implies verified provenance."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,field_validator,model_serializer,model_validator

Surface = Literal['repository','dependencies','secrets','iac','cloud','network','ai']


class ImmutableModel(BaseModel):
    model_config=ConfigDict(frozen=True,extra='forbid',hide_input_in_errors=True)

    @field_validator('repository',check_fields=False)
    @classmethod
    def repository_identity(cls,value):
        if any(part in {'.','..'} for part in value.split('/')):
            raise ValueError('Invalid repository identity')
        return value


class VerificationGate(ImmutableModel):
    name: str = Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
    # A registry digest, or a locally built content-addressed image ID (dependency test images).
    image: str = Field(pattern=r'^(?:[A-Za-z0-9./:_-]+@sha256:[a-f0-9]{64}|sha256:[a-f0-9]{64})$')
    argv: tuple[str,...] = Field(min_length=1,max_length=64)
    timeout_seconds: int = Field(default=300,ge=1,le=1800)
    network: Literal['none','egress']='none'
    required: bool=True
    # 'build': a larger scratch /tmp that allows executing files, for toolchains that compile and then run a
    # binary (go test). Still no network, read-only workspace, no capabilities.
    scratch: Literal['small','build']='small'

    @model_serializer(mode='wrap')
    def _stable(self,handler):
        # The default is left out so digests of every existing gate stay the same.
        data=handler(self)
        if data.get('scratch')=='small':data.pop('scratch')
        return data

    @field_validator('argv')
    @classmethod
    def bounded_arguments(cls,value):
        if any(not arg or '\x00' in arg or len(arg)>4096 for arg in value):
            raise ValueError('Invalid verification argv')
        return value


class ModelPricing(ImmutableModel):
    model_id: str=Field(min_length=1,max_length=256)
    input_microdollars_per_million: int=Field(ge=0,le=1000000000000)
    output_microdollars_per_million: int=Field(ge=0,le=1000000000000)


class RepositoryPolicy(ImmutableModel):
    schema_version: Literal[1]=1
    repository: str = Field(pattern=r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
    base_branch: str=Field(default='main',min_length=1,max_length=128)
    allowed_check_app_ids: tuple[int,...]=()
    base_revision: str = Field(pattern=r'^[a-f0-9]{40}$')
    expires_at: datetime
    allowed_scanners: tuple[str,...] = Field(min_length=1,max_length=64)
    allowed_surfaces: tuple[Surface,...]=('repository',)
    assessment_paths: tuple[str,...]=()
    allowed_paths: tuple[str,...] = Field(min_length=1,max_length=64)
    gates: tuple[VerificationGate,...] = Field(min_length=1,max_length=32)
    protected_paths: tuple[str,...]=()
    reproduction_gate: VerificationGate | None=None
    reproduction_rule_ids: tuple[str,...]=()
    reproduction_finding_fingerprints: tuple[str,...]=Field(default=(),max_length=128)
    verification_bundle_digest: str | None=Field(default=None,pattern=r'^[a-f0-9]{64}$')
    max_attempts: int=Field(default=3,ge=1,le=5)
    max_patch_bytes: int=Field(default=131072,ge=1,le=1048576)
    max_patch_files: int=Field(default=10,ge=1,le=100)
    writer_model: str=Field(default='gpt-4o',min_length=1,max_length=256)
    reviewer_model: str=Field(default='gpt-4o-mini',min_length=1,max_length=256)
    provider_base_url: str='https://api.openai.com/v1'
    provider_budget_microdollars: int=Field(default=0,ge=0,le=1000000000)
    model_pricing: tuple[ModelPricing,...]=()
    max_model_output_tokens: int=Field(default=4096,ge=256,le=16384)
    max_model_input_tokens: int=Field(default=196608,ge=1024,le=262144)
    auto_issue: bool=True
    auto_pr: bool=True
    auto_merge: bool=False
    required_github_checks: tuple[str,...]=()

    @field_validator('expires_at')
    @classmethod
    def aware_expiry(cls,value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('Scope expiry needs timezone')
        return value

    @model_validator(mode='after')
    def validate_policy(self):
        from mallace.remediation.policy import normalized_path
        from mallace.remediation.git_delivery import safe_branch
        safe_branch(self.base_branch)
        from urllib.parse import urlsplit
        provider=urlsplit(self.provider_base_url)
        if provider.username or provider.password or provider.query or provider.fragment or not provider.hostname:
            raise ValueError('Provider endpoint must be credential-free')
        if provider.scheme!='https' and not (provider.scheme=='http' and provider.hostname in {'localhost','127.0.0.1','::1'}):
            raise ValueError('Provider endpoint requires HTTPS or loopback')
        if self.writer_model.strip().casefold()==self.reviewer_model.strip().casefold():
            raise ValueError('Writer and reviewer models must differ')
        if len({price.model_id for price in self.model_pricing})!=len(self.model_pricing):
            raise ValueError('Model pricing identifiers must be unique')
        for path in self.allowed_paths+self.protected_paths+self.assessment_paths:
            normalized_path(path)
        if self.reproduction_gate is not None:
            if not self.reproduction_gate.required or self.reproduction_gate.network!='none' or not self.reproduction_rule_ids or not self.verification_bundle_digest:
                raise ValueError('Independent reproduction needs pinned bundle, rule coverage and no network')
        elif self.reproduction_rule_ids or self.verification_bundle_digest or self.reproduction_finding_fingerprints:
            raise ValueError('Incomplete reproduction policy')
        import re
        if any(not re.fullmatch('[a-f0-9]{64}',value) for value in self.reproduction_finding_fingerprints):
            raise ValueError('Invalid independent finding binding')
        if any(gate.network!='none' for gate in self.gates):
            raise ValueError('Verification egress is not supported without destination enforcement')
        if not any(gate.required for gate in self.gates):
            raise ValueError('At least one required verification gate is necessary')
        if len({gate.name for gate in self.gates})!=len(self.gates):
            raise ValueError('Verification gate names must be unique')
        if self.auto_merge and not self.auto_pr:
            raise ValueError('Auto merge requires PR delivery')
        if any(not isinstance(app,int) or isinstance(app,bool) or app<=0 for app in self.allowed_check_app_ids):
            raise ValueError('Invalid trusted check application')
        if self.auto_merge and not self.allowed_check_app_ids:
            raise ValueError('Auto merge requires trusted GitHub check application identities')
        if self.auto_merge and not self.required_github_checks:
            raise ValueError('Auto merge requires authoritative GitHub checks')
        return self


class SecurityEvidence(ImmutableModel):
    schema_version: Literal[1]=1
    repository: str=Field(pattern=r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
    revision: str=Field(pattern=r'^[a-f0-9]{40}$')
    surface: Surface
    scanner_id: str=Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
    rule_id: str=Field(min_length=1,max_length=256)
    path: str=Field(min_length=1,max_length=1024)
    line: int=Field(default=1,ge=1)
    execution_mode: Literal['live','mock','unknown']='unknown'
    validation: Literal['confirmed','unverified']='unverified'
    evidence_digest: str=Field(pattern=r'^[a-f0-9]{64}$')
    severity: Literal['critical','high','medium','low','info','unknown']='medium'
