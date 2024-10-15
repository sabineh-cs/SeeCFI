from pathlib import Path
from typing import List
from finder.Fingerprinter import Fingerprinter
from finder.MagicValuesExtensions import MagicValues, FileExtensions


class FileFinder:

    """
    Find all files of a given type and format.
    """

    def __init__(self, dir_path: Path,
                 magic_value_prefix: MagicValues,
                 file_extension: FileExtensions,
                 magic_values_blacklist=None):
        """
        Find all files of a given type and format.

        :param dir_path: Top directory given as user input
        :param magic_value_prefix: Magic value of the file format to find
        :param file_extension: Extension of the file format to find
        :param magic_values_blacklist: Blacklist of magic values to exclude
        """
        if magic_values_blacklist is None:
            magic_values_blacklist = []
        self.__dir_path = dir_path
        self.__magic_value_prefix = magic_value_prefix
        self.__file_extension = file_extension
        self.__magic_values_blacklist = magic_values_blacklist

    def find_all(self) -> List[Path]:
        """
        Find all files of a given type or format.

        :return: List of all files of a given type or format
        """
        matched_files = []
        for fingerprint in Fingerprinter.directory(self.__dir_path):
            magic_value = fingerprint.magic_value
            binary_name = fingerprint.binary_name
            if magic_value.startswith(str(self.__magic_value_prefix)) and \
                    not self.__is_magic_value_in_blacklist(binary_name) and \
                    self.__is_magic_value_extension_matching(binary_name):
                matched_files.append(fingerprint.file_path)
        return matched_files

    def __is_magic_value_in_blacklist(self, binary_name: str) -> bool:
        """
        Check if the magic value of a file is contained in the magic value blacklist.

        :param binary_name: name of the binary to check
        :return: Whether element in magic value blacklist
        """
        is_in_blacklist = False
        for value in self.__magic_values_blacklist:
            if value in binary_name:
                is_in_blacklist = True
                break
        return is_in_blacklist

    def __is_magic_value_extension_matching(self, binary_name: str) -> bool:
        """
        Check if the extension of the binary file matches the expected file extension.

        :param binary_name: name of binary to check
        :return: Whether extensions match
        """
        is_matching = False
        if str(self.__file_extension) in binary_name:
            is_matching = True
        return is_matching
