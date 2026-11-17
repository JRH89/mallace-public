"""Policy authority stays outside findings and model-generated content."""
from datetime import UTC,datetime
import hashlib
import json
from pathlib import PurePosixPath
import re


def normalized_path(path: str) -> str:
    if not path or '\\' in path or any(ord(char)<32 for char in path) or re.match(r'^[A-Za-z]:',path):
        raise ValueError('Unsafe repository path')
    if path.startswith('/') or any(segment in {'','.','..'} for segment in path.split('/')):
        raise ValueError('Unsafe repository path')
    return str(PurePosixPath(path))


def _under(path,prefix):
    return path==prefix or path.startswith(prefix+'/')


def credential_path(path):
    parts=[part.lower() for part in PurePosixPath(path).parts]
    protected={'.git','.gitconfig','.git-credentials','.hg','.svn','.aws','.ssh','.vercel','.mallace','.docker','.netrc','.npmrc','.pypirc','credentials','credentials.json','id_rsa','id_ed25519','mallace-policy.json'}
    return any(part in protected or part.startswith('.env') or part.endswith(('.pem','.key','.p12','.pfx')) for part in parts)


def validate_edit_path(path,policy):
    path=normalized_path(path)
    lower=path.lower()
    if credential_path(path):
        raise ValueError('Protected credential or metadata path')
    if _under(lower,'.github/workflows') or lower in {'.gitlab-ci.yml','jenkinsfile','azure-pipelines.yml','mallace-policy.json'} or _under(lower,'.circleci'):
        raise ValueError('Protected verification or policy path')
    if any(_under(path,prefix) for prefix in policy.protected_paths):
        raise ValueError('Protected repository path')
    if not any(_under(path,prefix) for prefix in policy.allowed_paths):
        raise ValueError('Path is outside authorized edit scope')
    return path


def validate_observation(evidence,policy,now=None):
    now=now or datetime.now(UTC)
    if now.tzinfo is None or now>=policy.expires_at:
        raise ValueError('Remediation authorization expired')
    if evidence.execution_mode!='live':
        raise ValueError('Live observation is required')
    if evidence.repository!=policy.repository or evidence.revision!=policy.base_revision:
        raise ValueError('Evidence repository or revision mismatch')
    if evidence.scanner_id not in policy.allowed_scanners or evidence.surface not in policy.allowed_surfaces:
        raise ValueError('Scanner or surface is outside authorized scope')
    path=normalized_path(evidence.path)
    if any(part.lower() in {'.git','.svn','.hg'} for part in path.split('/')):
        raise ValueError('Finding is outside committed repository scope')
    if policy.assessment_paths and not any(_under(path,prefix) for prefix in policy.assessment_paths):
        raise ValueError('Finding is outside authorized assessment paths')


def validate_eligibility(evidence,policy,now=None):
    validate_observation(evidence,policy,now)
    if evidence.validation!='confirmed':
        raise ValueError('Live confirmed evidence is required')


def validate_patch_eligibility(evidence,policy,now=None):
    validate_eligibility(evidence,policy,now)
    validate_edit_path(evidence.path,policy)
    if policy.reproduction_finding_fingerprints and finding_fingerprint(evidence) not in policy.reproduction_finding_fingerprints:
        raise ValueError('Independent probe is bound to another finding')


def canonical_digest(value):
    if hasattr(value,'model_dump'):
        value=value.model_dump(mode='json')
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def remediation_fingerprint(evidence,policy):
    return canonical_digest({'evidence':evidence.model_dump(mode='json'),'policy':policy.model_dump(mode='json')})


def fix_key(evidence):
    """Stable across commits: the same rule in the same file is the same fix, wherever the line moves."""
    return canonical_digest({key:getattr(evidence,key) for key in ('repository','rule_id','path')})


def finding_fingerprint(evidence):
    """Finding identity survives authorization-policy rotation and evidence refresh."""
    return canonical_digest({key:getattr(evidence,key) for key in ('repository','revision','surface','scanner_id','rule_id','path','line')})


class PublicationScopeDenied(ValueError):
    pass


def authorize_publication(evidence,policy):
    try:
        validate_eligibility(evidence,policy)
    except ValueError:
        raise PublicationScopeDenied('Publication scope is no longer valid') from None
