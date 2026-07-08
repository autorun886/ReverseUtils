from PySide6.QtWidgets import QApplication

from feeds.core.idahelper import IDA
from feeds.core.signals import probe_signals
from feeds.env import disable_history, revert_history


class SignatureProbe:
    def __init__(self):
        pass

    def process(self, signatures):
        try:
            hist = disable_history()
            probe_signals.start.emit(len(signatures))
            for item in signatures:
                path = item['path']
                row = item['row']
                IDA.create_undo()
                result = IDA.apply_sig_file(path)

                probe_signals.result.emit(result, row)
                probe_signals.update.emit(1)

                QApplication.processEvents()
                IDA.perform_undo()
            revert_history(hist)
        except Exception as e:
            print(e)
        finally:
            probe_signals.finish.emit()

    def label(self):
        return 'Run probe'
