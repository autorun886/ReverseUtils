import enum
import logging
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_diskio
import ida_funcs
import ida_idaapi
import ida_idp
import ida_libfuncs
import ida_loader
import ida_name
import ida_segment
import ida_undo
import idc

# from . import logger
logger = logging.getLogger(f'{__name__}')


class Target(enum.Enum):
    AARCH64_UNKNOWN_LINUX_GNU = 'aarch64-unknown-linux-gnu	'
    AARCH64_APPLE_DARWIN = 'aarch64-apple-darwin'
    I686_PC_WINDOWS_GNU = 'i686-pc-windows-gnu'
    I686_PC_WINDOWS_MSVC = 'i686-pc-windows-msvc'
    I686_UNKNOWN_LINUX_GNU = 'i686-unknown-linux-gnu'
    X86_64_APPLE_DARWIN = 'x86_64-apple-darwin'
    X86_64_PC_WINDOWS_GNU = 'x86_64-pc-windows-gnu'
    X86_64_PC_WINDOWS_MSVC = 'x86_64-pc-windows-msvc'
    X86_64_UNKNOWN_LINUX_GNU = 'x86_64-unknown-linux-gnu'
    # Seen in 1.77.2 manifest (ELF without std)
    X86_64_UNKNOWN_NONE = 'x86_64-unknown-none'


class SigHooks(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        self.matched_funcs = dict()

    def idasgn_matched_ea(self, ea, name, lib_name):
        self.matched_funcs[ea] = name


class IDA:
    def __init__(self):
        self.path = True

    @staticmethod
    def is_mingw() -> bool:
        ea1 = 0
        ea2 = ida_idaapi.BADADDR
        ea = ida_bytes.find_bytes('mingw-w64-crt'.encode(), ea1, ea2)
        if ea != ida_idaapi.BADADDR:
            logger.debug('Found mingw-w64-crt')
            return True
        ea = ida_bytes.find_bytes('Mingw-w64 runtime failure:'.encode(), ea1, ea2)
        if ea != ida_idaapi.BADADDR:
            logger.debug('Found Mingw-w64-runtime failure')
            return True
        return False

    @staticmethod
    def guess_target():
        file_type = ida_loader.get_file_type_name().casefold()
        logger.debug(f'file_type: {file_type}')

        if 'x86-64' in file_type or 'amd64' in file_type:
            if 'elf' in file_type:
                return Target.X86_64_UNKNOWN_LINUX_GNU
            elif 'portable' in file_type:
                if IDA.is_mingw():
                    return Target.X86_64_PC_WINDOWS_GNU
                return Target.X86_64_PC_WINDOWS_MSVC
        elif 'arm64' in file_type:
            if 'mach' in file_type:
                return Target.AARCH64_APPLE_DARWIN
            elif 'elf' in file_type:
                return Target.AARCH64_UNKNOWN_LINUX_GNU

        return None

    @staticmethod
    def is_rust_binary():
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, 'rust_begin_unwind')
        if ea != ida_idaapi.BADADDR:
            return True

        ea1 = 0
        ea2 = ida_idaapi.BADADDR
        segment = ida_segment.get_segm_by_name('.rodata')
        if segment is not None:
            ea1 = segment.start_ea
            ea2 = segment.end_ea

        ea = ida_bytes.find_bytes('rustc-'.encode(), ea1, ea2)

        return ea != ida_idaapi.BADADDR

    @staticmethod
    def get_ida_sig_dir():
        return ida_diskio.idadir(ida_diskio.SIG_SUBDIR)

    @staticmethod
    def get_ida_bin_dir():
        return idc.idadir()

    @staticmethod
    def get_ida_flair_dir() -> Path:
        return Path(idc.idadir()) / 'tools' / 'flair'

    @staticmethod
    def save_idb_copy(new_filename: str):
        try:
            if ida_loader.save_database(new_filename, 0):
                logger.debug(f'Database successfully saved to {new_filename}')
            else:
                logger.error(f'Failed to save the database to {new_filename}')
        except Exception as e:
            logger.error(f'An error occurred while saving the database: {e}')

    @staticmethod
    def get_applied_sigs_dict(intersect_with: {} = None):
        applied_sigs = {}
        for i in range(ida_funcs.get_idasgn_qty()):
            if ida_funcs.calc_idasgn_state(i) == ida_funcs.IDASGN_APPLIED:
                signame, _, nmatches = ida_funcs.get_idasgn_desc_with_matches(i)
                try:
                    path = ida_libfuncs.get_idasgn_path_by_short_name(signame)
                    if path is not None:
                        signame = os.path.realpath(path)
                except Exception:
                    pass

                applied_sigs[signame] = {'matches': nmatches}

        if intersect_with is not None:
            return {
                key: applied_sigs[key] for key in (applied_sigs.keys() & intersect_with.keys())
            }

        return applied_sigs

    @staticmethod
    def get_applied_sigs():
        applied_sigs = []
        for i in range(ida_funcs.get_idasgn_qty()):
            if ida_funcs.calc_idasgn_state(i) == ida_funcs.IDASGN_APPLIED:
                signame, optlibs, nmatches = ida_funcs.get_idasgn_desc_with_matches(i)
                applied_sigs.append((signame, optlibs, nmatches))

        return applied_sigs

    @staticmethod
    def get_sig_name(file):
        try:
            return ida_funcs.get_idasgn_title(file)
        except Exception as e:
            logger.error(f'{file}: {e}')
            return ''

    @staticmethod
    def create_undo(label: str = 'Initial state, auto analysis'):
        if ida_undo.create_undo_point('ida_feeds:', label):
            logger.info('Successfully created an undo point...')
        else:
            logger.error('Failed to created an undo point...')

    @staticmethod
    def perform_undo():
        if ida_undo.perform_undo():
            logger.info('Successfully reverted database changes...')
        else:
            logger.error('Failed to revert database changes...')

    @staticmethod
    def apply_sig_list(sig_list):
        for sig in sig_list:
            IDA.create_undo('Apply signature ' + Path(sig['path']).name)
            if not ida_funcs.plan_to_apply_idasgn(sig['path']):
                logger.error(f'plan_to_apply_idasgn() failed for {sig["path"]}')

                if not ida_auto.auto_wait():
                    break

    @staticmethod
    def get_sig_waiting_queue():
        items = 0
        for item in range(ida_funcs.get_idasgn_qty()):
            state = ida_funcs.calc_idasgn_state(item)
            # Count sig waiting (planned or currently applying)
            if state == ida_funcs.IDASGN_PLANNED or state == ida_funcs.IDASGN_CURRENT:
                items = items + 1
        return items

    @staticmethod
    def get_sig_index(sig_file_name: str):
        for index in range(0, ida_funcs.get_idasgn_qty()):
            fname, _, _ = ida_funcs.get_idasgn_desc_with_matches(index)
            if fname == sig_file_name:
                return index
        return -1

    @staticmethod
    def apply_sig_file(sig_file_name: str):
        if not os.path.isfile(sig_file_name):
            logger.error(f'The specified value {sig_file_name} is not a valid file name')
            return

        root, extension = os.path.splitext(sig_file_name)
        if extension != '.sig':
            logger.error(f'The specified value {sig_file_name} is not a valid sig file')
            return

        # Install hook on IDB to collect func_matches
        sig_hook = SigHooks()
        sig_hook.hook()

        # Start apply process and wait for it
        ida_funcs.plan_to_apply_idasgn(sig_file_name)
        idx = IDA.get_sig_index(sig_file_name)
        if idx < 0:
            return None

        iterations = 0
        while True:
            iterations += 1
            state = ida_funcs.calc_idasgn_state(idx)
            if state == ida_funcs.IDASGN_BADARG:
                break
            if state == ida_funcs.IDASGN_APPLIED:
                break
            if not ida_auto.auto_wait():
                break
            if iterations > 128:
                break

        matches = {
            'signature': sig_file_name,
            'matches': len(sig_hook.matched_funcs),
            'matched_functions': [],
        }

        for fea in sig_hook.matched_funcs:
            func_details = f'<0x{fea:x}> {sig_hook.matched_funcs[fea]}'
            matches['matched_functions'].append(func_details)
            matches['matched_functions'] = sorted(matches['matched_functions'])

        sig_hook.unhook()

        return matches
