import sys
from io import StringIO
import logging

logging = logging.getLogger(__name__)


def timeout_handler(signum, frame):
    raise TimeoutError('Generation of CFG took too long!')


def parse_irsb_node(node) -> []:
    """
    Parse IRSB node to get assembly code.

    :param node: CFG angr node
    :return: assembly representation of node
    """
    old_stdout = sys.stdout
    sys.stdout = result = StringIO()
    if node.block is not None:
        node.block.disassembly.pp()
    sys.stdout = old_stdout
    result = result.getvalue().splitlines()
    list_result = []
    for l in result:
        list_result.append(l.split('\t')[1:])
    return list_result


def parse_irsb_block(block):
    """
    Parse IRSB block to get assembly code.

    :param block: CFG angr block
    :return: Assembly representation of block
    """
    old_stdout = sys.stdout
    sys.stdout = result = StringIO()
    block.disassembly.pp()
    sys.stdout = old_stdout
    result = result.getvalue().splitlines()
    list_result = []
    for l in result:
        list_result.append(l.split('\t')[1:])
    return list_result


def transform_code(code) -> []:
    """
    Transform list of list instructions into list of instructions

    :param code: assembly representation of branching node
    :return: Transformed code -> only have one instruction per index
    """
    code.reverse()
    for i in range(len(code) - 1):
        if len(code[i]) > 1:
            operand = code[i][0]
            code[i] = code[i][1].split(', ')
            code[i].insert(0, operand)
    return code[2:]


def get_call_register(node) -> []:
    """
    Get list of registers used in call instructions -> identify indirect calls

    :param node: node to check for call instruction
    :return: List of registers used in call instruction
    """
    str_call_inst = parse_irsb_node(node)
    for sub_list in str_call_inst:
        if 'call' in sub_list:
            if '+' in sub_list[-1]:
                tmp_tmp = sub_list[-1].split(' +')
                tmp = tmp_tmp[0].split(' ')[-1]
                tmp = tmp.replace('[', '')
            elif '-' in sub_list[-1]:
                tmp_tmp = sub_list[-1].split(' -')
                tmp = tmp_tmp[0].split(' ')[-1]
                tmp = tmp.replace('[', '')
            else:
                tmp = sub_list[-1].split(' ')[-1]
            if len(tmp) > 8:
                return ''.join(e for e in tmp if is_register(e))
            elif is_register(tmp):
                tmp = tmp.replace('[', '')
                tmp = tmp.replace(']', '')
                return tmp
    return


def get_return_blocks(function) -> []:
    """
    Get all blocks of given function containing the return instruction.

    :param function: function to find return instructions in
    :return: All blocks in given function containing the return instruction
    """
    return_blocks = []
    for block in function.blocks:
        if 'ret' in str(block.disassembly.insns):
            return_blocks.append(parse_irsb_block(block))
    return return_blocks


def get_return_blocks_and_print(function) -> []:
    """
    Get all blocks of given function containing the return instruction.

    :param function: function to find return instructions in
    :return: All blocks in given function containing the return instruction
    """
    return_blocks = {}
    print_blocks = {}
    for block in function.blocks:
        if 'ret' in str(block.disassembly.insns):
            return_blocks[block] = parse_irsb_block(block)
            print_blocks[block] = block
    return return_blocks, print_blocks


def init_watch_list(register, cmp_params) -> []:
    """
    Initialize which regsiters need to be checked/monitored in order to verify
    if register used in protected call or jump was used as branching condition.

    :param register: register used in indirect jump or call
    :param cmp_params: conditional branching instruction
    :return: List of registers to monitor
    """
    watch_list = [register]
    cmp_params = cmp_params.split(', ')
    for op in cmp_params:
        if is_register(op):
            watch_list.append(op)
    return watch_list


def is_register(arg) -> bool:
    """
    Check if given arguments of instruction is a register.

    :param arg: argument to check
    :return: Whether arg is a register or numeric value such as address
    """
    return not arg.isnumeric() and not arg.startswith('0x')


def is_call_reg_modified(call_reg: str, node):
    """
    Check if the value of register, used for the indirect call, was modified before.

    :param call_reg: call register to check
    :param node: containing the call register and/or previous instructions

    :return: Whether call register has been modified
    """
    print(call_reg)
    str_call_inst = parse_irsb_node(node)
    print(str_call_inst)
    relevant_instructions = str_call_inst[:-1]
    for inst in relevant_instructions:
        tmp = inst[-1].split(', ')
        print(tmp)
        if call_reg in tmp[0]:
            return True
        else:
            return False
    return False
