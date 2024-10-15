import sys

from results.BinaryObject import BinaryObject
import checker.Helper as helper


class ShadowCallStackChecker:

    @staticmethod
    def run(cfg, binary_obj: BinaryObject):
        """
        Verify if binary was compiled using ShadowCallStack (backward-edge).

        :param cfg: generated CFG of binary to analyze
        :param binary_obj: corresponding binary object
        :return: Whether binary was compiled using ShadowCallStack
        """
        all_functions = cfg.functions.items()
        # Iterate through all functions of the binary
        for addr, function in all_functions:
            prologue = False
            # Verify that function return and is not an external one
            if function.has_return and not function.is_simprocedure:
                entry_block = helper.parse_irsb_block(function.get_block(addr))
                return_blocks = helper.get_return_blocks(function)
                # Verify that the ShadowCallStack is setup in the function's prologue
                for instruction in entry_block:
                    if len(instruction) == 2:
                        op, regs = instruction
                        if 'str' in op and 'x18' in regs:
                            prologue = True
                # Verify that ShadowCallStack is loaded in function's epilogue
                if prologue:
                    for block in return_blocks:
                        for instruction in block:
                            if len(instruction) == 2:
                                op, regs = instruction
                                if 'ldr' in op and 'x18' in regs:
                                    binary_obj.scs = True
                                    return
        return

    @staticmethod
    def run_all(cfg, binary_obj: BinaryObject, filename: str):
        """
        Verify if binary was compiled using ShadowCallStack (backward-edge).

        :param filename: file to dump assembly code
        :param cfg: generated CFG of binary to analyze
        :param binary_obj: corresponding binary object
        :return: Whether binary was compiled using ShadowCallStack
        """
        all_functions = cfg.functions.items()
        # Iterate through all functions of the binary
        with open(filename, 'a') as sys.stdout:
            for addr, function in all_functions:
                prologue = False
                # Verify that function return and is not an external one
                if function.has_return and not function.is_simprocedure:
                    entry_block = helper.parse_irsb_block(function.get_block(addr))
                    return_blocks, print_blocks = helper.get_return_blocks_and_print(function)
                    # Verify that the ShadowCallStack is setup in the function's prologue
                    for instruction in entry_block:
                        if len(instruction) == 2:
                            op, regs = instruction
                            if 'str' in op and 'x18' in regs:
                                prologue = True
                    # Verify that ShadowCallStack is loaded in function's epilogue
                    if prologue:
                        for key in return_blocks:
                            block = return_blocks[key]
                            for instruction in block:
                                if len(instruction) == 2:
                                    op, regs = instruction
                                    if 'ldr' in op and 'x18' in regs:
                                        binary_obj.scs = True
                                        print('\n--------Function--------\n')
                                        print(function)
                                        print('----------------\n')
                                        print(f'Entry block at {addr:#x} (prologue):')
                                        function.get_block(addr).disassembly.pp()
                                        print(f'Exit block (epilogue):')
                                        print_blocks[key].disassembly.pp()
        return
