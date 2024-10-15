import os
from pathlib import Path

from finder.FileFinder import FileFinder
from finder.MagicValuesExtensions import MagicValues, FileExtensions


class ElfBinariesFinder:
    """
    Find all ELF executables.
    """
    @staticmethod
    def find_all(top_dir_path: Path):
        """
        Find all binary files.

        :param top_dir_path: top directory given as user input
        :return: List of paths of all binaries
        """
        all_elf_binaries = FileFinder(
                dir_path=Path(top_dir_path),
                magic_value_prefix=MagicValues.ELF_MAGIC_VALUE,
                file_extension=FileExtensions.NO_EXTENSION,
                magic_values_blacklist=[
                    FileExtensions.OAT_FILE_EXTENSION,
                    FileExtensions.ODEX_FILE_EXTENSION
                ]
            ).find_all()
        return all_elf_binaries
