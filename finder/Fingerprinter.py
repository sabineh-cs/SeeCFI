import os
import magic
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List

logging = logging.getLogger(__name__)

@dataclass
class FileFingerprint:
    file_path: Path
    magic_value: str
    binary_name: str


class Fingerprinter:
    """
    Generate a fingerprint (=signature) for each file.
    """

    @staticmethod
    def directory(dir_path: Path) -> List[FileFingerprint]:
        """
        Iterate through all files and return their fingerprints

        :param dir_path: top directory given as user input
        :return: List of fingerprints (file's path, file's magic value, file's name)
        """
        all_files = Fingerprinter.__get_all_files(dir_path)
        logging.info(f'All files in directory {all_files}')
        file_fingerprints = []
        for file in all_files:
            try:
                if Path(file).is_file() or Path(file).is_dir():
                    fingerprint = FileFingerprint(
                        file_path=Path(file),
                        magic_value=magic.from_file(file), binary_name=Path(file).name
                    )
                    print(file)
                    file_fingerprints.append(fingerprint)
            except FileNotFoundError as e:
                # Occurs because of broken symbolic link
                logging.error(f'Could not find file {file}: {e}')
            except PermissionError as e:
                logging.error(f'No permission to open file {e}')

        return file_fingerprints

    @staticmethod
    def __get_all_files(top_dir_path: Path) -> []:
        """
        Extract all files contained in given image (user input)

        :param top_dir_path: top directory given as user input
        :return: List of all files
        """
        all_files = [os.path.join(dirpath, f)
                     for (dirpath, dirnames, filenames) in os.walk(top_dir_path)
                     for f in filenames]
        return all_files
