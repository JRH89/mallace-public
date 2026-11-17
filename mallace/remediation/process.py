"""Shell-free subprocess execution with shared output, time and process-group bounds."""
import os
import math
import selectors
import signal
import subprocess
import tempfile
import time


def run_bounded(argv,*,timeout=60,max_output=1048576,input_bytes=None,cwd=None,env=None,cancelled=None,termination_grace_seconds=0):
    if timeout<=0 or not 1<=max_output<=67108864 or input_bytes is not None and len(input_bytes)>16777216:
        raise ValueError('Invalid subprocess bounds')
    if type(termination_grace_seconds) not in (int,float) or not math.isfinite(termination_grace_seconds) or not 0<=termination_grace_seconds<=5:
        raise ValueError('Invalid termination grace')
    status='running';buffers={'stdout':bytearray(),'stderr':bytearray()};captured=0
    deadline=time.monotonic()+timeout
    with tempfile.TemporaryFile() as incoming:
        if input_bytes is not None:
            incoming.write(input_bytes);incoming.seek(0)
        process=subprocess.Popen(argv,cwd=cwd,env=env,stdin=incoming if input_bytes is not None else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ,'stdout')
                selector.register(process.stderr,selectors.EVENT_READ,'stderr')
                while (selector.get_map() or process.poll() is None) and status=='running':
                    if cancelled is not None and cancelled():
                        status='cancelled';break
                    remaining=deadline-time.monotonic()
                    if remaining<=0:
                        status='timed_out';break
                    if not selector.get_map():
                        time.sleep(min(.05,remaining));continue
                    for key,_ in selector.select(min(.1,remaining)):
                        chunk=os.read(key.fileobj.fileno(),4096)
                        if not chunk:
                            selector.unregister(key.fileobj);continue
                        available=max_output-captured
                        buffers[key.data].extend(chunk[:available]);captured+=min(available,len(chunk))
                        if len(chunk)>available:
                            status='output_limit';break
            if status=='running':
                try:
                    process.wait(timeout=max(.01,deadline-time.monotonic()));status='completed'
                except subprocess.TimeoutExpired:
                    status='timed_out'
        finally:
            if status!='completed' or process.poll() is None:
                if termination_grace_seconds and process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGINT)
                    except ProcessLookupError:pass
                    try:process.wait(timeout=termination_grace_seconds)
                    except subprocess.TimeoutExpired:pass
                try:
                    os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=10)
            process.stdout.close();process.stderr.close()
    return {'status':status,'returncode':process.returncode,**{key:bytes(value) for key,value in buffers.items()}}
