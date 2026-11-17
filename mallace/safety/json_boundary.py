"""Bounded unambiguous JSON for policy and external scanner inputs."""
import json
import math


def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key]=value
    return result


def load_json(content,*,max_bytes=1048576,max_depth=64,max_nodes=100000):
    if not isinstance(content,bytes) or len(content)>max_bytes:
        raise ValueError('JSON input exceeds byte limit')
    try:
        value=json.loads(content.decode('utf-8'),object_pairs_hook=unique_object,
                         parse_constant=lambda constant:(_ for _ in ()).throw(ValueError('Non-finite JSON value')))
    except (UnicodeError,json.JSONDecodeError,RecursionError):
        raise ValueError('Invalid JSON document') from None
    pending=[(value,0)];visited=0
    while pending:
        item,depth=pending.pop();visited+=1
        if depth>max_depth or visited>max_nodes:
            raise ValueError('JSON structure exceeds limit')
        if isinstance(item,float) and not math.isfinite(item):
            raise ValueError('Non-finite JSON value')
        if isinstance(item,dict):
            pending.extend((child,depth+1) for child in item.values())
        elif isinstance(item,list):
            pending.extend((child,depth+1) for child in item)
    return value


def read_bounded_file(path):
    """Read at most 1 MiB from a regular input file without following a final symlink."""
    import os
    import stat
    descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    with os.fdopen(descriptor,'rb') as handle:
        info=os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>1048576:
            raise ValueError('Input is not a bounded regular file')
        content=handle.read(1048577)
        if len(content)>1048576:
            raise ValueError('Input exceeds limit')
        return content
