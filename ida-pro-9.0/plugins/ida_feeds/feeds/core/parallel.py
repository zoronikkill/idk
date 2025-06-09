import rpyc
import shutil
import subprocess
from itertools import cycle
from time import sleep
import rpyc.utils.classic
import ida_diskio
import idc
from PyQt5.QtCore import *
from PyQt5.QtWidgets import QApplication
from feeds.env import *
from feeds.core.idahelper import IDA
from feeds.core.signals import WorkerSignals, probe_signals
from feeds.core.client import RpcClient

sysenv = os.environ.copy()
# Allow IDALIB to load when running the plugin
sysenv["IDA_IS_INTERACTIVE"] = "0"
sysenv["IDA_NO_HISTORY"] = "1"

# Set the IDADIR env just to make sure idalib will be able to locate
# the IDA installation folder in case the library is not yet configured
if sysenv.get("IDADIR", None) is None:
    sysenv["IDADIR"] = ida_diskio.idadir(None)

def start_process(port):
    process = None
    try:
        if platform.system() == "Windows":
            process = subprocess.Popen([SYS_INTERPRETER_PATH, SERVER_PY, str(port)], env=sysenv, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            process = subprocess.Popen([SYS_INTERPRETER_PATH, SERVER_PY, str(port)], env=sysenv)
    except Exception as e:
        print(e)
    return process

'''
RpcPipe
'''
class RpcPipe(QRunnable):
    def __init__(self, port, host='localhost'):
        super(RpcPipe, self).__init__()

        self.host = host
        self.port = port
        self.server = None
        self.client = None
        self.sig_list = []
        self.signals = WorkerSignals()
        self.dir = os.path.join(CACHE_DIR, 'procs', f'{self.port}')
        self.idb = os.path.join(self.dir, os.path.basename(idc.get_idb_path()))

    def start(self):
        self.server = start_process(str(self.port))
        self.client = RpcClient(self.host, self.port)
        sleep(1)  # TODO: add retries handling
        self.client.connect(os.path.join(self.dir, f'ida.log'))
        return self

    def stop(self):
        self.client.disconnect()
        self.server.wait()

    def prepare(self):
        try:
            if not os.path.exists(self.dir):
                os.makedirs(self.dir)
            val = disable_history()
            IDA.save_idb_copy(self.idb)
            revert_history(val)
        except Exception as e:
            print(e)
            pass

    pyqtSlot()
    def run(self):
        try:
            self.start()
            self.client.request("open_database", self.idb)
            for item in self.sig_list:
                path = item["path"]
                row = item["row"]
                self.client.request("create_undo")
                response = self.client.request("apply_signature", path)
                result = rpyc.utils.classic.obtain(response)
                probe_signals.result.emit(result, row)
                self.client.request("perform_undo")
                probe_signals.update.emit(1)

            self.client.request("close_database")
            self.stop()
        except Exception as e:
            probe_signals.error.emit(e)

    def process(self, thread_pool, sig_list):
        self.sig_list = sig_list
        thread_pool.start(self)

    def cleanup(self):
        try:
            shutil.rmtree(self.dir)
        except Exception as e:
            pass

class SignatureProbe:
    def __init__(self):
        self.ports = PORTS
        self.thread_pool = QThreadPool.globalInstance()

    def process(self, signatures):
        probe_signals.start.emit(len(signatures))
        def split_list(lst, n):
            # Initialize and distribute items across sub-lists
            slists = [[] for _ in range(n)]
            for i, item in enumerate(lst):
                slists[i % n].append(item)

            return slists

        sig_lists = split_list(signatures, len(self.ports))
        combined = list(zip(cycle(self.ports), sig_lists))
        try:
            QApplication.processEvents()
            for port, sig_sublist in combined:
                if len(sig_sublist) > 0:
                    rpc_pipe = RpcPipe(port)
                    # keep 'prepare' on the main thread
                    rpc_pipe.cleanup()
                    rpc_pipe.prepare()
                    rpc_pipe.process(thread_pool=self.thread_pool, sig_list=sig_sublist)
        except Exception as e:
            probe_signals.error.emit(e)
        finally:
            pass

    def label(self):
        return 'Run probe'
