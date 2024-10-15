import sys

from results.BinaryObject import BinaryObject
import checker.Helper as helper


class SingleModuleCFIChecker:

    @staticmethod
    def run(cfg, binary_obj: BinaryObject):
        """
        Verify if binary was compiled using basic CFI (forward-edge).

        :param cfg: generated CFG of binary to analyze
        :param binary_obj: corresponding binary object
        :return: Whether binary was compiled using basic CFI (single-module CFI)
        """
        branching_nodes = cfg.model.get_branching_nodes()
        relevant_branchings = []

        # Iterate through all extracted branching nodes and check that they only have two successors
        while len(branching_nodes):
            b = branching_nodes.pop()
            succ = b.successors
            if len(succ) == 2:
                relevant_branchings.append(b)

        # If no relevant branchings were found, return
        if len(relevant_branchings) == 0:
            return

        # Search for the CFI pattern
        for b_node in relevant_branchings:
            result: bool = False
            modified: bool = False
            res: bool = False
            one, two = b_node.successors
            if one is None or one.block is None or two is None or two.block is None:
                continue
            if 'ud' in str(one.block.disassembly.insns) and 'call' in str(two.block.disassembly.insns):
                res = check_compare_statement(b_node, two)
            if 'ud' in str(two.block.disassembly.insns) and 'call' in str(one.block.disassembly.insns):
                res = check_compare_statement(b_node, one)
            if res:
                result, modified = res
            if result:
                binary_obj.single_cfi = True
                binary_obj.modified = modified
                return
        return

    @staticmethod
    def run_all(cfg, binary_obj: BinaryObject, filename: str):
        """
        Verify if binary was compiled using basic CFI (forward-edge).

        :param filename: file to dump assembly code
        :param cfg: generated CFG of binary to analyze
        :param binary_obj: corresponding binary object
        :return: Whether binary was compiled using basic CFI (single-module CFI)
        """
        branching_nodes = cfg.model.get_branching_nodes()
        relevant_branchings = []

        # Iterate through all extracted branching nodes and check that they only have two successors
        while len(branching_nodes):
            b = branching_nodes.pop()
            succ = b.successors
            if len(succ) == 2:
                relevant_branchings.append(b)

        # If no relevant branchings were found, return
        if len(relevant_branchings) == 0:
            return

        # Search for the CFI pattern
        with open(filename, 'a') as sys.stdout:
            for b_node in relevant_branchings:
                result: bool = False
                modified: bool = False
                res: bool = False
                one, two = b_node.successors
                if one is None or one.block is None or two is None or two.block is None:
                    continue
                if 'ud' in str(one.block.disassembly.insns) and 'call' in str(two.block.disassembly.insns):
                    res = check_compare_statement(b_node, two)
                if 'ud' in str(two.block.disassembly.insns) and 'call' in str(one.block.disassembly.insns):
                    res = check_compare_statement(b_node, one)
                if res:
                    result, modified = res
                if result:
                    binary_obj.single_cfi = True
                    binary_obj.modified = modified
                    print('----------------\n')
                    print(f'Branching node at {b_node.addr:#x}:')
                    b_node.block.disassembly.pp()
                    print(f'First successor node at {one.addr:#x}')
                    one.block.disassembly.pp()
                    print(f'Second successor node at {two.addr:#x}:')
                    two.block.disassembly.pp()
        return


def check_compare_statement(branching_node, call_node) -> [bool, bool]:
    """
    Check if the condition of the conditional jump (branching) is based on register used in protected call

    :param branching_node: node containing conditional jump (branching)
    :param call_node: node containing protected call
    :return: Whether branching is based on register used in protected call
    """
    branching_code = helper.parse_irsb_node(branching_node)
    call_register = helper.get_call_register(call_node)
    # Iterate through instructions to check if branching based on call register
    for instructions in branching_code:
        if not call_register:
            continue
        if 'cmp' in instructions:
            cmp_inst = instructions[1:][0]
            if call_register in cmp_inst:
                return True, helper.is_call_reg_modified(call_register, call_node)
            else:
                # If protected call register not the same as in the cmp instruction
                #   Then trace back its value to see if value based on register used in protected call
                watch_list = helper.init_watch_list(call_register, cmp_inst)
                if trace_back_register(branching_code, watch_list):
                    return True, helper.is_call_reg_modified(call_register, call_node)
                else:
                    return False, False


def trace_back_register(branching_code, watch_list) -> bool:
    """
    Trace back the register used in compare statement to see if value based on register used in protected call.

    :param branching_code: assembly representation of the node containing the cmp instruction
    :param watch_list: list of registers that were used in the data flow of the register used in cmp
    :return: Whether compare instruction (branching) based on register used in protected call
    """
    transformed = helper.transform_code(branching_code)
    register = watch_list[0]
    for instr in transformed:
        if len(instr) > 2:
            if instr[1] in watch_list:
                if len(instr) == 4:
                    if not helper.is_register(instr[3]):
                        continue
                    else:
                        if instr[3] in register or register in instr[3]:
                            return True
                        else:
                            watch_list.append(instr[3])
                if not helper.is_register(instr[2]):
                    continue
                else:
                    if instr[2] in register or register in instr[2]:
                        return True
                    else:
                        watch_list.append(instr[2])
    return False









