"""Bounded runner-owned verification containers; never mount credentials or the Docker socket."""
from datetime import UTC,datetime
import hashlib
import os
import re
from pathlib import Path
import tempfile
import stat
import uuid
import time
from mallace.remediation.policy import canonical_digest,credential_path
from mallace.remediation.process import run_bounded


def docker_command(workspace,gate,name,verification_directory=None):
    workspace=Path(workspace).resolve(strict=True)
    if not workspace.is_dir() or ',' in str(workspace):
        raise ValueError('Unsafe verification workspace')
    command=['docker','run','--pull','never','--name',name,'--label','mallace.managed=true',
             '--label','mallace.sandbox-schema=1','--label',f'mallace.expires-at={int(time.time())+gate.timeout_seconds+10}',
             '--read-only','--network','none' if gate.network=='none' else 'bridge',
             '--cap-drop','ALL','--security-opt','no-new-privileges:true','--user',f'{os.getuid() or 65532}:{os.getgid() or 65532}',
             '--memory','1g' if gate.scratch=='build' else '512m','--cpus','1','--pids-limit','128',
             '--tmpfs','/tmp:rw,exec,nosuid,size=1g' if gate.scratch=='build' else '/tmp:rw,noexec,nosuid,size=64m','--workdir','/workspace',
             '--mount',f'type=bind,src={workspace},dst=/workspace,readonly']
    job=os.environ.get('MALLACE_MAINTENANCE_JOB_ID')
    if job is not None:
        if not re.fullmatch('[a-f0-9]{32}',job):raise ValueError('Invalid maintenance sandbox owner')
        command+=['--label','mallace.maintenance-job='+job]
    if verification_directory is not None:
        verification=Path(verification_directory).resolve(strict=True)
        if not verification.is_dir() or ',' in str(verification):
            raise ValueError('Unsafe independent verification directory')
        command+=['--mount',f'type=bind,src={verification},dst=/verification,readonly']
    return command+[gate.image,*gate.argv]


def _run_staged_gate(workspace,gate,*,verification_directory=None,max_output_bytes=65536):
    if not 1024<=max_output_bytes<=1048576:
        raise ValueError('Invalid gate output limit')
    name='mallace-gate-'+uuid.uuid4().hex
    command=docker_command(workspace,gate,name,verification_directory)
    started=datetime.now(UTC).isoformat()
    status='failed';exit_code=None;stdout=b'';stderr=b''
    try:
        result=run_bounded(command,timeout=gate.timeout_seconds,max_output=max_output_bytes)
        stdout,stderr=result['stdout'],result['stderr']
        exit_code=result['returncode']
        status=('passed' if exit_code==0 else 'failed') if result['status']=='completed' else result['status']
    finally:
        # Never accept a passing gate whose owned sandbox cannot be removed.
        try:
            removed=run_bounded(['docker','rm','--force',name],timeout=10,max_output=4096)
            if removed['status']!='completed' or removed['returncode']!=0:
                status='cleanup_failed'
        except OSError:
            status='cleanup_failed'
    return {'gate':gate.name,'gate_digest':canonical_digest(gate),'image':gate.image,
            'status':status,'exit_code':exit_code,'captured_bytes':len(stdout)+len(stderr),
            'output_digest':canonical_digest({'stdout':hashlib.sha256(stdout).hexdigest(),'stderr':hashlib.sha256(stderr).hexdigest()}),
            'started_at':started,'finished_at':datetime.now(UTC).isoformat(),
            'failure_kind':failure_kind(stdout+b'\n'+stderr) if exit_code not in (0,77) else None}


_ERROR_NAME=re.compile(rb'\b([A-Z][A-Za-z]{1,40}(?:Error|Exception|Failure))\b')


def failure_kind(output):
    """The last exception class name in a test's output (e.g. ModuleNotFoundError), or a short marker for a
    compile failure. Only this label ever leaves the gate; the output itself is digested, never kept."""
    if re.search(rb'(?m)^# [\w./-]+\n|: undefined: |cannot use .* as |declared and not used',output):return 'GoCompileError'
    if b'PHP Parse error' in output or b'PHP Fatal error' in output:return 'PHPFatalError'
    if b'ERR_MODULE_NOT_FOUND' in output:return 'ERR_MODULE_NOT_FOUND'
    names=_ERROR_NAME.findall(output)
    return names[-1].decode() if names else None


_credential_path=credential_path


def _stage_tree(source,destination):
    source=Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Verification source must be a real directory')
    total=0;count=0;excluded=0
    for folder,dirs,files in os.walk(source,followlinks=False):
        relative=Path(folder).relative_to(source)
        kept=[]
        for name in dirs:
            path=relative/name
            if _credential_path(path):
                excluded+=1
                continue
            if (Path(folder)/name).is_symlink():
                raise ValueError('Verification source contains a symlink')
            kept.append(name)
        dirs[:]=kept
        target=destination/relative
        target.mkdir(parents=True,exist_ok=True,mode=0o700)
        for name in files:
            relative_path=relative/name
            if _credential_path(relative_path):
                excluded+=1
                continue
            path=Path(folder)/name
            descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
            with os.fdopen(descriptor,'rb') as handle:
                info=os.fstat(handle.fileno());count+=1;total+=info.st_size
                if not stat.S_ISREG(info.st_mode) or info.st_size>10485760 or total>67108864 or count>10000:
                    raise ValueError('Verification snapshot exceeds file/type/size limits')
                content=handle.read(10485761)
                if len(content)!=info.st_size:
                    raise ValueError('Verification source changed while staging')
            output=target/name
            with output.open('xb') as handle:
                handle.write(content)
            output.chmod(0o700 if info.st_mode&0o111 else 0o600)
    return excluded


def run_gate(workspace,gate,*,verification_directory=None,max_output_bytes=65536):
    if gate.network!='none':
        raise ValueError('Gate egress requires destination enforcement; unsupported')
    with tempfile.TemporaryDirectory(prefix='mallace-verification-') as temporary:
        staged=Path(temporary)/'workspace'
        excluded=_stage_tree(workspace,staged)
        verification=None
        if verification_directory is not None:
            verification=Path(temporary)/'verification'
            excluded+=_stage_tree(verification_directory,verification)
        receipt=_run_staged_gate(staged,gate,verification_directory=verification,max_output_bytes=max_output_bytes)
        receipt['excluded_paths']=excluded
        return receipt
