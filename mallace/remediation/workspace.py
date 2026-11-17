"""Private Git revision workspaces exported from raw blobs, with checkout hooks/filters disabled."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from mallace.remediation.policy import normalized_path
from mallace.remediation.process import run_bounded


_GIT_OPTIONS=['--no-replace-objects','--no-pager','-c','gc.auto=0','-c','maintenance.auto=false','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','commit.gpgSign=false','-c','core.untrackedCache=false']


def git(repository,*arguments,input_bytes=None,max_output=1048576):
    environment={key:value for key,value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_ALLOW_PROTOCOL='',GIT_GRAFT_FILE='/dev/null')
    result=run_bounded(['git',*_GIT_OPTIONS,'-C',str(repository),*arguments],input_bytes=input_bytes,max_output=max_output,env=environment)
    if result['status']!='completed' or result['returncode']!=0:
        raise RuntimeError('Bounded Git operation failed')
    return result['stdout']


@contextmanager
def isolated_revision(source,revision,*,paths=None,authorize=None):
    authorize=authorize or (lambda: None)
    authorize()
    if paths is not None:
        paths=tuple(normalized_path(path) for path in paths)
        if not paths:
            raise ValueError('Scoped revision export requires paths')
    source=Path(source).resolve(strict=True)
    if not re.fullmatch('[a-f0-9]{40}',revision):
        raise ValueError('Exact Git revision is required')
    resolved=git(source,'rev-parse','--verify',revision+'^{commit}').decode().strip()
    if resolved!=revision:
        raise ValueError('Revision mismatch')
    commit=git(source,'cat-file','commit',revision)
    _verify_object('commit',commit,revision)
    tree_line=commit.split(b'\n',1)[0].decode('ascii')
    if not re.fullmatch('tree [a-f0-9]{40}',tree_line):
        raise ValueError('Malformed pinned commit tree')
    tree=tree_line.split()[1]
    _verify_object('tree',git(source,'cat-file','tree',tree,max_output=2097152),tree)
    entries=git(source,'ls-tree','-rzt','--full-tree',revision,max_output=2097152).split(b'\x00')
    files=[];total=0
    for entry in entries:
        if not entry:
            continue
        authorize()
        header,raw_path=entry.split(b'\t',1)
        mode,kind,blob=header.decode('ascii').split()
        path=normalized_path(raw_path.decode('utf-8'))
        if mode=='040000' and kind=='tree':
            _verify_object('tree',git(source,'cat-file','tree',blob,max_output=2097152),blob)
            continue
        if mode not in {'100644','100755'} or kind!='blob' or any(part.lower()=='.git' for part in path.split('/')):
            raise ValueError('Revision contains unsupported symlink/submodule/metadata')
        if paths is not None and not any(path==prefix or path.startswith(prefix+'/') for prefix in paths):
            continue
        authorize()
        size=int(git(source,'cat-file','-s',blob).decode())
        total+=size
        if size>10485760 or total>67108864 or len(files)>=10000:
            raise ValueError('Revision workspace exceeds limits')
        files.append((path,mode,blob,size))
    with tempfile.TemporaryDirectory(prefix='mallace-candidate-') as temporary:
        destination=Path(temporary)/'repository'
        # --no-checkout avoids source-controlled attributes invoking host filters.
        authorize()
        git(source,'worktree','add','--no-checkout','--detach',str(destination),revision)
        try:
            for path,mode,blob,size in files:
                authorize()
                content=git(source,'cat-file','blob',blob,max_output=max(1,size+1))
                _verify_object('blob',content,blob)
                if len(content)!=size:
                    raise ValueError('Git blob size mismatch')
                target=destination/path;target.parent.mkdir(parents=True,exist_ok=True)
                with target.open('xb') as handle:
                    handle.write(content)
                target.chmod(0o700 if mode=='100755' else 0o600)
            git(destination,'read-tree',revision)
            authorize()
            yield destination
        finally:
            git(source,'worktree','remove','--force',str(destination))


def workspace_digest(workspace):
    root=Path(workspace)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Workspace digest requires a real directory')
    digest=hashlib.sha256();total=0;count=0
    for folder,dirs,files in os.walk(root,followlinks=False):
        dirs[:]=sorted(name for name in dirs if name!='.git')
        if any((Path(folder)/name).is_symlink() for name in dirs):
            raise ValueError('Workspace contains directory symlink')
        for name in sorted(files):
            path=Path(folder)/name;relative=path.relative_to(root).as_posix()
            if relative=='.git':
                continue
            descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
            with os.fdopen(descriptor,'rb') as handle:
                info=os.fstat(handle.fileno());total+=info.st_size;count+=1
                if not stat.S_ISREG(info.st_mode) or info.st_size>10485760 or total>67108864 or count>10000:
                    raise ValueError('Workspace exceeds file/type/size bounds')
                content=handle.read(10485761)
            digest.update(relative.encode()+b'\x00'+str(bool(info.st_mode&0o111)).encode()+b'\x00'+hashlib.sha256(content).digest())
    return digest.hexdigest()


def commit_candidate(workspace,paths):
    if not paths:
        raise ValueError('No candidate changes')
    for path in paths:
        path=normalized_path(path)
        target=Path(workspace)/path
        if target.is_symlink() or not target.is_file():
            raise ValueError('Candidate file is unsafe')
        content=target.read_bytes()
        blob=git(workspace,'hash-object','-w','--stdin',input_bytes=content).decode().strip()
        mode='100755' if target.stat().st_mode&0o111 else '100644'
        git(workspace,'update-index','--add','--cacheinfo',mode,blob,path)
    tree=git(workspace,'write-tree').decode().strip()
    parent=git(workspace,'rev-parse','HEAD').decode().strip()
    head=git(workspace,'-c','user.name=Mallace Runner','-c','user.email=mallace-runner@users.noreply.github.com',
        'commit-tree',tree,'-p',parent,'-m','Apply policy-bound Mallace remediation').decode().strip()
    git(workspace,'update-ref','HEAD',head,parent)
    return head


def _verify_object(kind,content,identity):
    digest=hashlib.sha1(kind.encode()+b' '+str(len(content)).encode()+b'\x00'+content).hexdigest()
    if digest!=identity:
        raise ValueError('Pinned Git object content does not match its identity')


def raw_commit_parents(repository,revision):
    if not re.fullmatch('[a-f0-9]{40}',revision):
        raise ValueError('Exact Git revision is required')
    content=git(repository,'cat-file','commit',revision)
    _verify_object('commit',content,revision)
    headers=content.split(b'\n\n',1)[0].splitlines()
    return [line[len(b'parent '):].decode('ascii') for line in headers if line.startswith(b'parent ')]
