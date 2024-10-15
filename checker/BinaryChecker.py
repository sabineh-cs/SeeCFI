from pathlib import Path
from typing import Union

import angr
import logging
import signal
import os

import global_variables
from checker import Helper
from results.BinaryObject import BinaryObject
from checker.SingleModuleCFIChecker import SingleModuleCFIChecker
from checker.MultiModuleCFIChecker import MultiModuleCFIChecker
from checker.ShadowCallStackChecker import ShadowCallStackChecker

from angr import Project


class BinaryChecker:
    """
    Generates BinaryObjects and performs analysis.
    """

    def __init__(self, binary: Path, image: str, special_file: str, linux: bool, skipDB=False, ignore_unsafe=False,
                 skip_db_check=False, load=True, only_multi_cfi=False):
        """
        Only load binary and generate CFG if it does not exist in database.

        :param binary: path to binary file to analyze
        :param image: subimage containing binary file
        :special_file: if file is .deb or .apex, otherwise empty
        :linux: set if image is a linux system
        :skipDB: only analyze a single binary and not a complete image
        :ignore_unsafe: analyze all binaries and not only memory-unsafe
        :skip_db_check: do not check if the binary already exists in the database
        :load: only generate CFG if set
        :only_multi_cfi: only check for multi-module CFI
        """
        self.logging = logging.getLogger(__name__)
        self.analyze: bool = False
        self.binary: Path = binary
        self.binary_obj: BinaryObject = self.__create_binary_obj(image, special_file)
        self.skip_db_check: bool = skip_db_check
        if skipDB:
            self.already_exits = False
        else:
            self.already_exits: bool = self.__exists_in_database()

        if load and only_multi_cfi and self.binary_obj.unsafe_language and (
                not self.already_exits or self.skip_db_check):
            self.logging.info(f'Analyzing {self.binary_obj.to_string()}')
            self.proj: Project = self.__load_binary()
            self.analyze = True

        elif load and self.binary_obj.unsafe_language and (not self.already_exits or self.skip_db_check):
            self.logging.info(f'Analyzing {self.binary_obj.to_string()}')
            self.proj: Project = self.__load_binary()
            self.cfg = self.__generate_cfg()
            signal.alarm(0)
            self.analyze = True

        elif load and ((not self.already_exits and self.binary_obj.unsafe_language) or
                       (linux and ignore_unsafe and (not self.binary_obj.unsafe_language or self.__has_single_cfi())) or
                       (not linux and ignore_unsafe and not self.binary_obj.unsafe_language)):
            self.logging.info(f'Analyzing {self.binary_obj.to_string()}')
            self.proj: Project = self.__load_binary()
            self.cfg = self.__generate_cfg()
            signal.alarm(0)
            self.analyze = True

        else:
            self.proj = None
            self.cfg = None
            if self.already_exits:
                self.logging.info(f'Binary already exists in database {binary.name}')

    def __load_binary(self) -> Union[Project, None]:
        """
        Try to load binary if not possible store error message in binary object.

        :return: angr project or None if binary could not be loaded by angr
        """
        try:
            return angr.Project(self.binary, main_opts={'base_addr': 0x100000})
        except Exception as e:
            logging.exception('Invalid binary', e)
            self.binary_obj.error = self.binary_obj.error + f'ERROR: Could not load binary because of {e}'
            print('ERROR: Could not load binary because of ', e)
            return None

    def __create_binary_obj(self, image: str, special_file: str) -> BinaryObject:
        """

        :param image: Subimage containing binary file
        :return: Initialized BinaryObject
        """
        path: Path = self.binary
        return BinaryObject(path, image, special_file)

    def __generate_cfg(self):
        """
        Try to generate CFG if not possible store error message in binary object.

        :return: angr CFG or None if CFG could not be generated
        """
        signal.signal(signal.SIGALRM, Helper.timeout_handler)
        signal.alarm(900)
        try:
            return self.proj.analyses.CFGFast()
        except Exception as e:
            logging.exception(f'CFG generation failed {e}')
            self.binary_obj.error = self.binary_obj.error + f'ERROR: Could not generate CFG because of {e}'
            print(f'ERROR: Could not generate CFG because of {e}')
            return None

    def run_all_checks(self, dump_assembly=False, single_module=False, only_multi_module=False, filename='') \
            -> BinaryObject:
        """
        Analyze the binary if it was compiled from a memory-unsafe language.

        :return: Updated BinaryObject
        """
        if self.proj is not None:
            if only_multi_module:
                MultiModuleCFIChecker.run(self.proj, self.binary_obj)
            elif dump_assembly:
                if single_module:
                    MultiModuleCFIChecker.run(self.proj, self.binary_obj)
                    if self.cfg is not None:
                        SingleModuleCFIChecker.run_all(self.cfg, self.binary_obj, filename)
                elif not MultiModuleCFIChecker.run(self.proj, self.binary_obj) and self.cfg is not None:
                    SingleModuleCFIChecker.run_all(self.cfg, self.binary_obj, filename)
                if self.cfg is not None:
                    ShadowCallStackChecker.run_all(self.cfg, self.binary_obj, filename)
            elif single_module:
                MultiModuleCFIChecker.run(self.proj, self.binary_obj)
                if self.cfg is not None:
                    SingleModuleCFIChecker.run(self.cfg, self.binary_obj)
                    ShadowCallStackChecker.run(self.cfg, self.binary_obj)
            else:
                if not MultiModuleCFIChecker.run(self.proj, self.binary_obj) and self.cfg is not None:
                    SingleModuleCFIChecker.run(self.cfg, self.binary_obj)
                if self.cfg is not None:
                    ShadowCallStackChecker.run(self.cfg, self.binary_obj)
        return self.binary_obj

    def __exists_in_database(self, binary_path=None) -> bool:
        """
        Check if binary object already exists in database.

        :param binary_path: possible to check based on BinaryPath
        :return: Whether binary exists in database
        """
        if binary_path:
            query = 'SELECT * FROM BinaryFile WHERE Subimage LIKE ? AND BinaryPath LIKE ?;'
            global_variables.cursor.execute(query, (self.binary_obj.image, '%' + binary_path,))
        else:
            query = 'SELECT * FROM BinaryFile WHERE Id LIKE ?;'
            global_variables.cursor.execute(query, (self.binary_obj.id,))
        rows = global_variables.cursor.fetchall()
        if len(rows) > 0:
            return True
        else:
            return False

    def __has_single_cfi(self) -> bool:
        """
        Check in database if binary object is compiled using single-module CFI.

        :return: Whether binary was compiled using single-module CFI
        """
        query = 'SELECT * FROM BinaryFile WHERE Id LIKE ? and Single_CFI = 1;'
        global_variables.cursor.execute(query, (self.binary_obj.id,))
        rows = global_variables.cursor.fetchall()
        if len(rows) > 0:
            return True
        return False

    def __has_multi_cfi(self, binary_path: str) -> bool:
        """
        Check in database if binary object is compiled using multi-module CFI.

        :return: Whether binary was compiled using multi-module CFI
        """
        query = 'SELECT * FROM BinaryFile WHERE Subimage LIKE ? AND BinaryPath LIKE ? AND Multi_CFI = 1;'
        global_variables.cursor.execute(query, (self.binary_obj.image, '%' + binary_path,))
        rows = global_variables.cursor.fetchall()
        if len(rows) > 0:
            return True

        return False

    def __update_lib32(self):
        """
        Update database if Lib32 error.
        """
        query = 'UPDATE BinaryFile SET Multi_CFI=1, Error=? WHERE Subimage LIKE ? AND Id LIKE ?;'
        global_variables.cursor.execute(query, ('Lib32', self.binary_obj.image, self.binary_obj.id,))
        logging.info(f'Updating {self.binary_obj} due to Lib32 error')
        global_variables.connection.commit()

    def __prepare_path(self) -> tuple[str, str]:
        """
        Generate the /lib and /lib64 path for a binary to check.

        :return: /lib and /lib64 path
        """
        original_path = self.binary_obj.path.as_posix()
        splitted = original_path.split('/lib/')
        if len(splitted) == 2:
            prefix = splitted[0].split('/')
            if len(prefix) > 1:
                path_part = prefix[-1]
                return os.path.join(path_part, 'lib', splitted[1]), os.path.join(path_part, 'lib64', splitted[1])

    def fix_lib32(self):
        """
        Check and if needed update 32-bit binary due to Lib32 error.
        """
        try:
            path32, path64 = self.__prepare_path()
            if not self.__has_multi_cfi(path32):
                if self.__exists_in_database(binary_path=path64) and self.__has_multi_cfi(path64):
                    self.__update_lib32()
        except Exception as e:
            logging.info(f'Could not check lib32 due to {e}.')
