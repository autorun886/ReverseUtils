import os
import signal
import sys
from pathlib import Path

import rpyc
from rpyc.utils.server import OneShotServer

try:
    import idapro
except ImportError as e:
    # idapro package may not be installed, try to locate the idalib module using IDADIR
    ida_dir = os.environ.get('IDADIR', None)
    if ida_dir is None:
        # Nothing to do, raise the error
        raise e
    # Add the $IDADIR/idalib/python folder to the sys path and try again
    sys.path.append(str(Path(ida_dir) / 'idalib' / 'python'))
    import idapro

from feeds.core import logger
from feeds.core.idahelper import IDA as wrapper


def disable_history():
    try:
        if 'IDA_NO_HISTORY' in os.environ:
            value = os.environ['IDA_NO_HISTORY']
            os.environ['IDA_NO_HISTORY'] = '1'
            return value
        else:
            os.environ['IDA_NO_HISTORY'] = '1'
            return None
    except Exception:
        pass


def revert_history(value):
    try:
        if value is not None:
            if 'IDA_NO_HISTORY' in os.environ:
                os.environ['IDA_NO_HISTORY'] = value
        else:
            os.environ.pop('IDA_NO_HISTORY')
    except Exception:
        pass


class FeedsService(rpyc.Service):
    def on_connect(self, conn):
        sys.stdout.write = conn.root.stdout_write
        sys.stderr.write = conn.root.stderr_write
        logger.info(f'Client connected to worker on port {self.port}')

    def on_disconnect(self, conn):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    def exposed_open_database(self, path):
        val = disable_history()
        result = idapro.open_database(path, True)
        revert_history(val)
        return result

    def exposed_close_database(self):
        val = disable_history()
        idapro.close_database(False)
        revert_history(val)

    def exposed_apply_signature(self, path):
        val = disable_history()
        result = wrapper.apply_sig_file(path)
        revert_history(val)
        return result

    def exposed_create_undo(self):
        val = disable_history()
        wrapper.create_undo()
        revert_history(val)

    def exposed_perform_undo(self):
        val = disable_history()
        wrapper.perform_undo()
        revert_history(val)


def signal_handler(sig, frame):
    logger.debug('Shutting down...')
    server.close()


if __name__ == '__main__':
    idapro.enable_console_messages(False)
    port = int(sys.argv[1])
    logger.debug(f'Started server on port {port}')

    service = FeedsService()
    service.port = port

    server = OneShotServer(
        service,
        port=port,
        protocol_config={'sync_request_timeout': 240, 'allow_pickle': True},
    )

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    val = disable_history()
    server.start()
    revert_history(val)
    logger.debug(f'Stopped server on port {port}')
