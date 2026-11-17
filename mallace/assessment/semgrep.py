"""Pinned offline code pattern assessment (Python, JavaScript/TypeScript, PHP, Ruby); complete reported target coverage required."""
from datetime import UTC,datetime
import hashlib
import re
from pathlib import Path
import tempfile
import uuid
from pydantic import model_validator
from mallace.assessment.secrets import AssessmentScope,_authorize,_safe_metadata
from mallace.remediation.contracts import SecurityEvidence,VerificationGate
from mallace.remediation.policy import canonical_digest,normalized_path,credential_path
from mallace.remediation.process import run_bounded
from mallace.remediation.sandbox import docker_command
from mallace.remediation.workspace import git,isolated_revision
from mallace.safety.json_boundary import load_json

SCANNER_ID='semgrep-1.184.0-mallace-code-v15'
# Big repositories (e.g. Juice Shop, ~550 files) take about two minutes on one core.
SCAN_SECONDS=600
PINNED_IMAGE='semgrep/semgrep@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed'
RULE_IDS={'mallace.python.'+suffix for suffix in ('dynamic-eval','dynamic-exec','shell-command','yaml-load','pickle-load','sql-query-construction','reflected-xss','ssrf','stored-xss','path-traversal')}|\
    {'mallace.javascript.'+suffix for suffix in ('command-injection','dynamic-eval','sql-query-construction','reflected-xss','ssrf','stored-xss','path-traversal','nosql-injection')}|\
    {'mallace.php.'+suffix for suffix in ('command-injection','dynamic-eval','unsafe-unserialize','sql-query-construction','reflected-xss','stored-xss','path-traversal')}|\
    {'mallace.ruby.'+suffix for suffix in ('command-injection','dynamic-eval','unsafe-deserialization','sql-query-construction','reflected-xss','stored-xss','path-traversal')}|\
    {'mallace.go.'+suffix for suffix in ('command-injection','sql-query-construction','template-injection','reflected-xss','stored-xss','path-traversal')}|\
    {'mallace.java.'+suffix for suffix in ('command-injection','unsafe-deserialization','sql-query-construction','path-traversal','reflected-xss')}
PYTHON_SUFFIXES=('.py',)
JAVASCRIPT_SUFFIXES=('.js','.mjs','.cjs','.ts','.mts','.cts')
PHP_SUFFIXES=('.php',)
RUBY_SUFFIXES=('.rb','.rake')
GO_SUFFIXES=('.go',)
JAVA_SUFFIXES=('.java',)
SOURCE_SUFFIXES=PYTHON_SUFFIXES+JAVASCRIPT_SUFFIXES+PHP_SUFFIXES+RUBY_SUFFIXES+GO_SUFFIXES+JAVA_SUFFIXES
RULE_FILES=('python.yml','javascript.yml','php.yml','ruby.yml','go.yml','java.yml')


def language_for(path):
    if path.endswith(PYTHON_SUFFIXES):return 'python'
    if path.endswith(JAVASCRIPT_SUFFIXES) and not path.endswith(('.d.ts','.d.mts','.d.cts','.min.js')):return 'javascript'
    if path.endswith(PHP_SUFFIXES) and not path.endswith('.blade.php'):return 'php'
    if path.endswith(RUBY_SUFFIXES):return 'ruby'
    if path.endswith(GO_SUFFIXES) and not path.endswith('_test.go'):return 'go'
    if path.endswith(JAVA_SUFFIXES):return 'java'
    return None


# Third-party browser libraries copied into an app (Rails app/assets, static/js): their findings are the
# library's, not the app's. Skipped files are counted in coverage as omitted.
_LIBRARY=re.compile(r'(^|[/])((jquery|bootstrap|moment|angular|lodash|underscore|backbone|d3|chart|highcharts|'
                    r'react|react-dom|vue|ember|handlebars|mustache|modernizr|popper|select2|datatables|'
                    r'knockout|prototype|scriptaculous|mootools|zepto|require|socket\.io)([.-][\w.-]*)?\.js|[^/]+\.min\.js)$',re.I)


def _vendored(path):
    return any(part in {'node_modules','bower_components','vendor'} for part in path.split('/')) or bool(_LIBRARY.search(path))


class SemgrepScope(AssessmentScope):
    allowed_scanners: tuple[str,...]=()
    image: str=PINNED_IMAGE

    @model_validator(mode='after')
    def explicit_grant(self):
        if SCANNER_ID not in self.allowed_scanners or self.image!=PINNED_IMAGE:
            raise ValueError('Scanner/image is not explicitly supported and authorized')
        return self


def _logical_path(value):
    if not isinstance(value,str):
        raise ValueError('Invalid scanner location')
    for prefix in ('/workspace/repository/','repository/'):
        if value.startswith(prefix):
            path=normalized_path(value[len(prefix):]);_safe_metadata(path)
            return path
    raise ValueError('Unexpected scanner location root')


# Files that do not parse (real repositories have a few, e.g. deliberately broken snippets) are reported as
# unparsed instead of failing the scan. Any other scanner error still fails it.
_PARSE_ERRORS={'Syntax error','Lexical error','PartialParsing','Other syntax error'}


def normalize_report(content,scope,receipt_digest,presented,unscanned=None):
    report=load_json(content)
    if not isinstance(report,dict) or report.get('version')!='1.184.0' or not isinstance(report.get('errors'),list):
        raise ValueError('Scanner reported errors or an unexpected version')
    unparsed=set()
    for error in report['errors']:
        kind=error.get('type') if isinstance(error,dict) else None
        kind=kind[0] if isinstance(kind,list) and kind else kind
        if not isinstance(kind,str) or kind not in _PARSE_ERRORS:
            raise ValueError('Scanner reported errors or an unexpected version')
        path=_logical_path(error.get('path'))
        if path not in presented:
            raise ValueError('Scanner reported an error outside presented source')
        unparsed.add(path)
    paths=report.get('paths')
    scanned=paths.get('scanned') if isinstance(paths,dict) else None
    if not isinstance(scanned,list) or len(scanned)>10000:
        raise ValueError('Scanner did not report bounded target coverage')
    normalized=[_logical_path(path) for path in scanned]
    # Never more than was presented; files the scanner skipped (e.g. .rake) are reported, not hidden.
    if len(set(normalized))!=len(normalized) or not set(normalized)<=presented:
        raise ValueError('Scanner reported incomplete or unexpected target coverage')
    if unscanned is not None:
        unscanned['unparsed']=sorted(unparsed);unscanned['skipped']=sorted(presented-set(normalized))
    results=report.get('results')
    if not isinstance(results,list) or len(results)>1000:
        raise ValueError('Scanner findings exceed report contract')
    findings=[]
    for record in results:
        if not isinstance(record,dict) or record.get('check_id') not in RULE_IDS:
            raise ValueError('Unexpected scanner rule')
        path=_logical_path(record.get('path'))
        start=record.get('start');line=start.get('line') if isinstance(start,dict) else None
        if path not in presented or type(line) is not int:
            raise ValueError('Finding is outside presented source')
        rule=record['check_id']
        findings.append(SecurityEvidence(repository=scope.repository,revision=scope.revision,surface='repository',
            scanner_id=SCANNER_ID,rule_id=rule,path=path,line=line,execution_mode='live',validation='unverified',
            evidence_digest=canonical_digest({'receipt':receipt_digest,'path':path,'line':line,'rule':rule}),
            severity='medium').model_dump(mode='json'))
    return findings


def scan_semgrep(source,scope):
    _authorize(scope)
    for value in (scope.repository,*scope.paths):
        _safe_metadata(value)
    remote=git(source,'config','--get','remote.origin.url').decode().strip()
    if remote not in {f'https://github.com/{scope.repository}',f'https://github.com/{scope.repository}.git',f'git@github.com:{scope.repository}.git'}:
        raise ValueError('Source origin does not match assessment repository')
    bundles={name:(Path(__file__).parent/'rules'/name).read_bytes() for name in RULE_FILES}
    rules=b''.join(name.encode()+b'\0'+content for name,content in bundles.items())
    if len(rules)>131072:
        raise ValueError('Trusted rule bundle exceeds limit')
    base={'schema_version':1,'scanner_id':SCANNER_ID,'repository':scope.repository,'revision':scope.revision,
        'scope_digest':canonical_digest(scope),'started_at':datetime.now(UTC).isoformat()}
    with isolated_revision(source,scope.revision,paths=scope.paths,authorize=lambda:_authorize(scope)) as workspace:
        with tempfile.TemporaryDirectory(prefix='mallace-code-scanner-') as temporary:
            temporary=Path(temporary);staged=temporary/'workspace';staged.mkdir(mode=0o700)
            repository=staged/'repository';repository.mkdir(mode=0o700)
            (staged/'.semgrepignore').write_bytes(b'')
            presented=set();size=0;omitted=0
            for candidate in sorted(workspace.rglob('*')):
                if not candidate.is_file():
                    continue
                path=candidate.relative_to(workspace).as_posix()
                if path=='.git':
                    continue
                if language_for(path) is None or _vendored(path) or credential_path(path):
                    omitted+=1;continue
                _authorize(scope);_safe_metadata(path)
                target=repository/path;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                content=candidate.read_bytes();target.write_bytes(content);target.chmod(0o600)
                presented.add(path);size+=len(content)
            coverage={'surfaces':['repository'] if presented else [],'languages':sorted({language_for(path) for path in presented}),'paths':list(scope.paths),
                'files_presented':len(presented),'bytes_presented':size,'files_omitted':omitted,
                'rules':sorted(RULE_IDS),'history_scanned':False,'untracked_files_scanned':False,
                'unsupported_surfaces':['dependencies','secrets','iac','cloud','network','ai']}
            if not presented:
                _authorize(scope)
                return {**base,'status':'no_coverage','receipt':None,'findings':[],'coverage':coverage,'finished_at':datetime.now(UTC).isoformat()}
            tools=temporary/'rules';tools.mkdir(mode=0o700)
            for name,content in bundles.items():(tools/name).write_bytes(content)
            argv=('scan',*(item for name in RULE_FILES for item in ('--config','/verification/'+name)),'--json','--oss-only','--no-rewrite-rule-ids',
                '--disable-nosem','--disable-version-check','--metrics','off','--no-git-ignore','--novcs',
                '--project-root','/workspace','--timeout','0','--jobs','1','--max-target-bytes','11000000','/workspace')
            gate=VerificationGate(name='semgrep-python',image=scope.image,argv=argv,timeout_seconds=SCAN_SECONDS)
            name='mallace-gate-'+uuid.uuid4().hex
            command=docker_command(staged,gate,name,tools)
            index=command.index(scope.image)
            command[index:index]=['--env','HOME=/tmp','--env','SEMGREP_ENABLE_VERSION_CHECK=0',
                '--env','SEMGREP_SEND_METRICS=off','--entrypoint','semgrep']
            _authorize(scope)
            try:
                result=run_bounded(command,timeout=SCAN_SECONDS,max_output=8388608)
                if result['status']!='completed' or result['returncode']!=0:
                    raise RuntimeError('Scanner did not complete successfully')
            finally:
                removed=run_bounded(['docker','rm','--force',name],timeout=10,max_output=4096)
                if removed['status']!='completed' or removed['returncode']!=0:
                    raise RuntimeError('Scanner sandbox cleanup incomplete')
            _authorize(scope)
            receipt={'scope_digest':base['scope_digest'],'image':scope.image,'rules_digest':hashlib.sha256(rules).hexdigest(),
                'adapter_digest':canonical_digest({'argv':argv,'entrypoint':'semgrep','home':'/tmp','metrics':'off','version_check':False,'staging':'code-empty-ignore-v6'}),'report_digest':hashlib.sha256(result['stdout']).hexdigest(),
                'target_digest':canonical_digest(sorted(presented)),'exit_code':0,'revision':scope.revision}
            unscanned={}
            findings=normalize_report(result['stdout'],scope,canonical_digest(receipt),presented,unscanned)
            coverage['files_unparsed']=len(unscanned['unparsed']);coverage['files_skipped']=len(unscanned['skipped'])
            coverage['files_unscanned_sample']=(unscanned['unparsed']+unscanned['skipped'])[:20]
    return {**base,'status':'completed','receipt':receipt,'findings':findings,'coverage':coverage,'finished_at':datetime.now(UTC).isoformat()}
