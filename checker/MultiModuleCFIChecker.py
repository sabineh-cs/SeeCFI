import angr
import subprocess
from results.BinaryObject import BinaryObject


def grep_cfi(binary: str, pattern: str) -> bool:
    """
    Use /bin/grep to check if binary contains a given pattern.

    :param binary: binary file to check/grep
    :param pattern: pattern to search for in binary file
    :return: Whether binary matches given pattern
    """
    output = subprocess.run([f'grep -i {pattern} {binary}'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if b'matches' in output.stdout or b'matches' in output.stderr:
        return True
    return False


class MultiModuleCFIChecker:

    @staticmethod
    def run(proj: angr.Project, binary_obj: BinaryObject) -> bool:
        """
        Verify if binary was compiled using Cross-DSO (forward-edge).
        Check if the symbols __cfi_slowpath and __cfi_check are present in the binary.

        :param proj: loaded binary file to analyze
        :param binary_obj: corresponding binary object
        :return: Whether binary was compiled using Cross-DSO (multi-module CFI)
        """
        filename = proj.filename
        name: str = filename.split('/')[-1]
        slowpath_check_sym: str = str(proj.loader.find_symbol('__cfi_slowpath'))
        cfi_check_sym: str = str(proj.loader.find_symbol('__cfi_check'))
        if cfi_check_sym == 'None':
            cfi_check_sym = ''
        if slowpath_check_sym == 'None':
            slowpath_check_sym = ''
        cfi_check: bool = name in cfi_check_sym

        if ((grep_cfi(filename, '"__cfi"') and cfi_check)
                or (grep_cfi(filename, '"__cfi"') and cfi_check_sym and slowpath_check_sym)
                or (slowpath_check_sym and cfi_check)
                or (grep_cfi(filename, '"cfi-check-fail"') and not cfi_check_sym and not slowpath_check_sym)):
            binary_obj.multi_cfi = True
            return True
        else:
            return False
