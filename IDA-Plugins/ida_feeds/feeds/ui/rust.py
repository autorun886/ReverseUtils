import pathlib
from collections import defaultdict
from typing import Any, Dict, Union

from PySide6.QtCore import QObject, QRunnable, Signal

from feeds.core.idahelper import IDA
from feeds.rust import git
from feeds.rust.rust import guess_rustc_hash_or_version

from . import logger

dependencies_loaded = True
failed_dependency = []
try:
    from feeds.rust import rust, sigmake
except ImportError as e:
    dependencies_loaded = False
    failed_dependency.append(e.name)


def get_rust_info(binary: pathlib.Path) -> Dict[str, Any]:
    info = defaultdict(str, {})
    try:
        info['target'] = IDA.guess_target()
        result = guess_rustc_hash_or_version(binary)
        if result is not None:
            k, v = result
            info[k] = v
        else:
            return info

        if info.get('hash') and not info.get('version'):
            info['version'] = git.commit_to_tag(info['hash'])

    except Exception as rust_info_error:
        logger.warning(f'Failed to guess rust info for {binary}: {rust_info_error}')

    logger.debug(f'rust info: {info}')

    return info


def process(info: Dict, flair: pathlib.Path) -> Union[pathlib.Path, None]:
    try:
        maker = sigmake.Sigmake.create(flair)
    except Exception:
        raise
    else:
        return rust.make_signature(
            maker,
            info,
        )


class SigmakeWorkerSignals(QObject):
    # Result sig
    done = Signal(pathlib.Path)
    # Error
    error = Signal(str)
    # Progress message
    message = Signal(str)


class SigmakeWorker(QRunnable):
    def __init__(self, info: {}, flair_path: pathlib.Path):
        super().__init__()
        self.flair_path = flair_path
        self.info = info
        self.emitter = SigmakeWorkerSignals()

    def run(self):
        if dependencies_loaded:
            self.emitter.message.emit('Creating signature, please wait...')
            try:
                sig_path = process(self.info, self.flair_path)
                self.emitter.message.emit(f'Signature created: {sig_path}')
                self.emitter.done.emit(sig_path)
            except Exception as SigmakeWorkerError:
                self.emitter.message.emit('Failed to create signature')
                self.emitter.error.emit(str(SigmakeWorkerError))
        else:
            self.emitter.error.emit(
                f'Missing dependencies {failed_dependency}, please install the required libraries from requirements.txt'
            )
