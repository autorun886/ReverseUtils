#!/usr/bin/env python3

import sys
sys.path.append("..")

import argparse
import struct
import angr

import am_graph
from util import *

import logging
logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.ERROR)
# logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)


def load_project(filename):
    load_options = {
        'auto_load_libs': False,
        'main_opts': {'base_addr': 0},
    }
    try:
        return angr.Project(filename, load_options=load_options)
    except Exception:
        # Some dumped/packed ELFs have intentionally broken section headers.
        # cle checks RELRO before its own "discard section headers" fallback.
        from cle.backends.elf import metaelf

        original_get_relro = metaelf._get_relro

        def safe_get_relro(elf):
            try:
                return original_get_relro(elf)
            except Exception:
                return metaelf.Relro.PARTIAL

        metaelf._get_relro = safe_get_relro
        return angr.Project(filename, load_options=load_options)


def resolve_addr(project, addr):
    main_obj = project.loader.main_object
    if main_obj.contains_addr(addr):
        return addr

    linked_base = getattr(main_obj, "linked_base", 0) or 0
    rebased = addr + main_obj.mapped_base - linked_base
    if main_obj.contains_addr(rebased):
        print("[*] rebase input address %#x -> %#x" % (addr, rebased))
        return rebased

    return addr


def main():
    parser = argparse.ArgumentParser(description="debogus control flow script")
    parser.add_argument("-f", "--file", help="binary to analyze")
    parser.add_argument(
        "--addr", help="address of target function in hex format")
    args = parser.parse_args()

    if args.file is None or args.addr is None:
        parser.print_help()
        sys.exit(0)

    filename = args.file
    start = int(args.addr, 16)

    project = load_project(filename)
    start = resolve_addr(project, start)
    cfg = project.analyses.CFGFast(
        normalize=True,
        force_complete_scan=False,
        force_segment=True,
        function_starts=[start],
    )
    target_function = cfg.functions.get(start)
    if target_function is None:
        target_function = project.kb.functions.function(
            start,
            create=True,
            name="target_%x" % start,
        )
        cfg = project.analyses.CFGFast(
            normalize=True,
            force_complete_scan=False,
            force_segment=True,
            function_starts=[start],
        )
        target_function = cfg.functions.get(start)
    if target_function is None:
        raise RuntimeError("target function %#x was not found by CFGFast" % start)
    supergraph = am_graph.to_supergraph(target_function.transition_graph)

    base_addr = project.loader.main_object.mapped_base >> 12 << 12

    state = project.factory.blank_state(addr=target_function.addr, remove_options={
                                        angr.sim_options.LAZY_SOLVES})

    flow = set()
    flow.add(target_function.addr)

    print('*******************symbolic execution*********************')
    sm = project.factory.simulation_manager(state)
    sm.step()
    while len(sm.active) > 0:
        for active in sm.active:
            flow.add(active.addr)
        sm.step()

    print('executed blocks: ', list(map(hex, flow)))

    print('************************patch******************************')

    with open(filename, 'rb') as origin:
        origin_data = bytearray(origin.read())
        origin_data_len = len(origin_data)

    patch_nodes = set()
    for node in supergraph.nodes():
        if node.addr in patch_nodes:
            continue

        if node.addr not in flow:
            # patch unnecessary node
            file_offset = project.loader.main_object.addr_to_offset(node.addr)
            fill_nop(origin_data, file_offset, node.size, project.arch)
        else:
            suc_nodes = list(supergraph.successors(node))
            jmp_targets = []

            for suc_node in suc_nodes:
                if suc_node.addr in flow:
                    jmp_targets.append(suc_node.addr)
                else:
                    # patch unnecessary suc_node
                    file_offset = project.loader.main_object.addr_to_offset(suc_node.addr)
                    fill_nop(origin_data, file_offset,
                             suc_node.size, project.arch)
                    patch_nodes.add(suc_node.addr)

            # patch jmp instruction
            if len(suc_nodes) > 1 and len(jmp_targets) == 1:
                if project.arch.name in ARCH_X86:
                    file_offset = project.loader.main_object.addr_to_offset(node.addr + node.size) - 6
                    # nop + jmp
                    patch_value = OPCODES['x86']['nop'] + ins_j_jmp_hex_x86(node.addr + node.size - 5, jmp_targets[0], 'jmp')
                    patch_instruction(origin_data, file_offset, patch_value)
                elif project.arch.name in ARCH_ARM:
                    file_offset = project.loader.main_object.addr_to_offset(node.addr + node.size) - 4
                    patch_value = ins_b_jmp_hex_arm(node.addr + node.size - 4, jmp_targets[0], 'b')
                    if project.arch.memory_endness == 'Iend_BE':
                        patch_value = patch_value[::-1]
                    patch_instruction(origin_data, file_offset, patch_value)
                elif project.arch.name in ARCH_ARM64:
                    file_offset = project.loader.main_object.addr_to_offset(node.addr + node.size) - 4
                    patch_value = ins_b_jmp_hex_arm64(node.addr + node.size - 4, jmp_targets[0], 'b')
                    if project.arch.memory_endness == 'Iend_BE':
                        patch_value = patch_value[::-1]
                    patch_instruction(origin_data, file_offset, patch_value)

    assert len(origin_data) == origin_data_len, "Error: size of data changed!!!"

    recovery_file = filename + '_recovered'
    with open(recovery_file, 'wb') as recovery:
       recovery.write(origin_data)

    print('Successful! The recovered file: %s' % recovery_file)


if __name__ == "__main__":
    main()
