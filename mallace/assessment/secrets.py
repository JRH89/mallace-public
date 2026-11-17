"""Offline pattern assessment of pinned Git blobs; no credential validation or customer code."""
from datetime import UTC,datetime
import hashlib
import re
from pydantic import Field,field_validator
from mallace.remediation.contracts import ImmutableModel,SecurityEvidence
from mallace.remediation.policy import canonical_digest,normalized_path
from mallace.remediation.workspace import git,isolated_revision
from mallace.safety.redaction import redact_publication_credentials


class AssessmentScope(ImmutableModel):
    repository: str=Field(pattern=r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
    revision: str=Field(pattern=r'^[a-f0-9]{40}$')
    expires_at: datetime
    paths: tuple[str,...]=Field(min_length=1,max_length=64)

    @field_validator('paths')
    @classmethod
    def safe_paths(cls,value):
        for path in value:
            normalized_path(path)
            if any(part.lower() in {'.git','.hg','.svn'} for part in path.split('/')):
                raise ValueError('Repository metadata is outside assessment scope')
        return value

    @field_validator('expires_at')
    @classmethod
    def aware_expiry(cls,value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('Assessment expiry requires timezone')
        return value


# Versioned built-in rules, never sourced from the repository being assessed.
_RULES=(
    ('github-classic-token',rb'(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9])'),
    ('github-fine-grained-token',rb'(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{40,255}(?![A-Za-z0-9_])'),
    ('private-key-header',rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
)
SCANNER_ID='mallace-secret-patterns-v1'
RULESET_DIGEST=canonical_digest({name:pattern.decode('ascii') for name,pattern in _RULES})


def _authorize(scope):
    if scope.expires_at<=datetime.now(UTC):
        raise ValueError('Assessment scope expired')


def _safe_metadata(value):
    if redact_publication_credentials(value)!=value:
        raise ValueError('Credential-bearing assessment metadata is not publishable')


def scan_secrets(source,scope):
    """Return redacted observations and coverage. A clean result is not a security certification."""
    _authorize(scope)
    for value in (scope.repository,*scope.paths):
        _safe_metadata(value)
    remote=git(source,'config','--get','remote.origin.url').decode().strip()
    if remote not in {f'https://github.com/{scope.repository}',f'https://github.com/{scope.repository}.git',f'git@github.com:{scope.repository}.git'}:
        raise ValueError('Source origin does not match assessment repository')
    observations=[];files=0;size=0
    started=datetime.now(UTC).isoformat()
    with isolated_revision(source,scope.revision,paths=scope.paths,authorize=lambda: _authorize(scope)) as workspace:
        for candidate in sorted(workspace.rglob('*')):
            path=candidate.relative_to(workspace).as_posix()
            if path=='.git' or not candidate.is_file():
                continue
            if not any(path==prefix or path.startswith(prefix+'/') for prefix in scope.paths):
                continue
            _authorize(scope)
            _safe_metadata(path)
            content=candidate.read_bytes();files+=1;size+=len(content)
            content_digest=hashlib.sha256(content).hexdigest()
            for rule,pattern in _RULES:
                for match in re.finditer(pattern,content):
                    line=content.count(b'\n',0,match.start())+1
                    digest=canonical_digest({'rule':rule,'ruleset':RULESET_DIGEST,'blob':content_digest,'offset':match.start()})
                    observations.append(SecurityEvidence(repository=scope.repository,revision=scope.revision,
                        surface='secrets',scanner_id=SCANNER_ID,rule_id=rule,path=path,line=line,
                        evidence_digest=digest,execution_mode='live',validation='unverified',severity='high').model_dump(mode='json'))
                    if len(observations)>1000:
                        raise ValueError('Secret finding count exceeds limit; narrow assessment paths')
    _authorize(scope)
    return {'schema_version':1,'status':'completed' if files else 'no_coverage',
        'scanner_id':SCANNER_ID,'ruleset_digest':RULESET_DIGEST,'scope_digest':canonical_digest(scope),
        'repository':scope.repository,'revision':scope.revision,'started_at':started,
        'finished_at':datetime.now(UTC).isoformat(),'findings':observations,
        'coverage':{'surfaces':['secrets'],'paths':list(scope.paths),'files_scanned':files,'bytes_scanned':size,
            'rules':[name for name,_ in _RULES],'credential_validity_checked':False,
            'history_scanned':False,'untracked_files_scanned':False,
            'unsupported_surfaces':['repository','dependencies','iac','cloud','network','ai']}}
