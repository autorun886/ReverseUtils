from PySide6.QtCore import QObject, Signal


class WorkerSignals(QObject):
    start = Signal(int)
    finish = Signal()
    error = Signal(object)
    result = Signal(object, object)
    update = Signal(int)


probe_signals = WorkerSignals()


class UISignals(QObject):
    filter_path = Signal(object)
    refresh = Signal(bool)
    process_finished = Signal()


ui_signals = UISignals()
