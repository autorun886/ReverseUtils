import glob
import os
import pathlib
import platform
import subprocess
from typing import List

from feeds.core.idahelper import Target

from . import logger


class SigmakeNotFoundException(Exception):
    pass


class SigmakePlatformException(Exception):
    pass


class SigmakePatException(Exception):
    pass


class SigmakeUnknownError(Exception):
    pass


EXE_EXTENSION = str()
if platform.system() == 'Windows':
    EXE_EXTENSION = '.exe'

_TARGET_TO_PAT_TOOL = {
    Target.X86_64_PC_WINDOWS_GNU: 'pcf',
    Target.X86_64_PC_WINDOWS_MSVC: 'pcf',
    Target.X86_64_UNKNOWN_LINUX_GNU: 'pelf',
    Target.AARCH64_APPLE_DARWIN: 'pmacho',
}


def target_to_pat_tool(target: Target) -> str:
    tool = _TARGET_TO_PAT_TOOL.get(target)
    if not tool:
        raise SigmakePatException(f'Unsupported target {target}')
    return tool


class Sigmake:
    def __init__(self, flair_bin: pathlib.Path):
        self.flair_bin = flair_bin

    @classmethod
    def create(cls, flair: pathlib.Path) -> 'Sigmake':
        sigmakes = glob.glob(os.path.join(flair, 'sigmake' + EXE_EXTENSION))
        if not sigmakes:
            raise SigmakeNotFoundException(f'No sigmake found in {flair}')

        return cls(pathlib.Path(sigmakes[0]).parent)

    def pat_tool(self, target: Target) -> pathlib.Path:
        return self.flair_bin / (target_to_pat_tool(target) + EXE_EXTENSION)

    def sigmake_tool(self) -> pathlib.Path:
        return self.flair_bin / ('sigmake' + EXE_EXTENSION)

    def zipsig_tool(self) -> pathlib.Path:
        return self.flair_bin / ('zipsig' + EXE_EXTENSION)

    def make_pat(self, target: Target, pat_dest: pathlib.Path, sources: List[pathlib.Path]):
        # Split functions inside sections
        if platform.system() == 'Windows':
            subprocess.check_output(
                [self.pat_tool(target), '-S', *sources, pat_dest],
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            subprocess.check_output([self.pat_tool(target), '-S', *sources, pat_dest])

    def make_sig(self, name: str, sig_dest: pathlib.Path, pat_src: pathlib.Path):
        exc_path = sig_dest.with_suffix('.exc')

        sigmake_cmd = [
            str(self.sigmake_tool()),
            f'-n{name}',
            str(pat_src),
            str(sig_dest),
        ]
        logger.debug(f'Running {sigmake_cmd}')
        if platform.system() == 'Windows':
            cmd = subprocess.run(sigmake_cmd, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            cmd = subprocess.run(sigmake_cmd)

        if cmd.returncode != 0:
            resolve_collisions(exc_path)

        # Run again
        try:
            logger.debug(f'Running {sigmake_cmd} a 2nd time')
            if platform.system() == 'Windows':
                subprocess.check_call(sigmake_cmd, creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                subprocess.check_call(sigmake_cmd)
        except subprocess.CalledProcessError as _:
            raise SigmakeUnknownError('sigmake failed a second time')

        logger.info('Running zipsig')
        if platform.system() == 'Windows':
            subprocess.check_call(
                [self.zipsig_tool(), sig_dest],
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            subprocess.check_call([self.zipsig_tool(), sig_dest])


def resolve_collisions(exc_path: pathlib.Path):
    # TODO: resolve collisions properly

    with open(exc_path, 'r') as f:
        lines = f.readlines()

    with open(exc_path, 'w') as out:
        out.writelines(line for line in lines if not line.startswith(';'))
