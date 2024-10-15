import logging
from pathlib import Path
from typing import List, Union

from checker.BinaryChecker import BinaryChecker
from results.ImageObject import ImageObject
from results.OperatingSystemObject import OperatingSystemObject
from results.SpecialFileObject import SpecialFileObject


class ImageAnalysis:

    def __init__(self, os: str, factory_image_dir: Path,
                 ignore_unsafe: bool, only_multi_cfi: bool, skip_db_check: bool, linux=False):
        self.linux: bool = linux
        self.image_top_dir: Path = factory_image_dir
        self.os_obj: OperatingSystemObject = OperatingSystemObject(os, self.image_top_dir.name)
        self.ignore_unsafe: bool = ignore_unsafe
        self.only_multi_cfi: bool = only_multi_cfi
        self.skip_db_check: bool = skip_db_check
        self.special_file_obj: SpecialFileObject
        self.image_obj: Union[ImageObject, None] = None
        self.logging = logging.getLogger(__name__)

    def run_checker(self, all_elf_binaries: List[Path], image_id: str, special_file=' '):
        """
        Iterate through list of binaries, if not exists in database run checks and add to database.

        :param special_file:
        :param all_elf_binaries: List of all binaries to be analyzed
        :param image_id: Id (OS Version + image name) of the mounted subimage
        """
        for binary in all_elf_binaries:
            if self.ignore_unsafe:
                checker = BinaryChecker(binary, image_id, special_file, self.linux,
                                        ignore_unsafe=True, skip_db_check=self.skip_db_check)
            else:
                checker = BinaryChecker(binary, image_id, special_file, self.linux, skip_db_check=self.skip_db_check,
                                        only_multi_cfi=self.only_multi_cfi)
            logging.info(f'Next binary to analyze: {binary}')
            logging.info(f'Does binary exist in database?: {checker.already_exits}')
            logging.info(f'Binary info: {checker.binary_obj.to_string()}')

            if self.ignore_unsafe and checker.analyze:
                logging.info(f'Option: check unsafe binaries')
                binary_obj = checker.run_all_checks()
                if checker.already_exits:
                    logging.info(f'Updating database')
                    binary_obj.update_database(ignore_unsafe=True)
                else:
                    logging.info(f'Add to database')
                    binary_obj.add_to_database()

            elif (not checker.already_exits or checker.skip_db_check) and checker.analyze:
                logging.info(f'Add to database')
                if self.only_multi_cfi:
                    logging.info(f'Only checking for multi-module CFI')
                    binary_obj = checker.run_all_checks(only_multi_module=True)
                else:
                    binary_obj = checker.run_all_checks()
                if checker.already_exits:
                    binary_obj.update_database()
                else:
                    binary_obj.add_to_database()

            elif checker.analyze:
                logging.info(f'Updating database -> fixing old implementation mistake')
                binary_obj = checker.run_all_checks()
                binary_obj.update_database(ignore_unsafe=True)

        for binary in all_elf_binaries:
            if str(binary).__contains__('/lib/'):
                checker = BinaryChecker(binary, image_id, special_file, self.linux, skip_db_check=self.skip_db_check, load=False)
                logging.info(f'Check if binary {binary} need update.')
                checker.fix_lib32()
