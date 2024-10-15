import hashlib
import subprocess
import os
import time
from pathlib import Path
import global_variables
import logging


class BinaryObject:

    def __init__(self, path: Path, image: str, specialfile: str):
        self.name: str = path.name
        self.image: str = image
        self.specialfile: str = specialfile
        self.path: Path = path
        self.timestamp: str = self.__get_timestamp()
        self.checksum: str = self.__calculate_checksum()
        self.unsafe_language: bool = self.__check_compiler()
        self.modified: bool = False
        self.error: str = ''
        self.multi_cfi: bool = False
        self.single_cfi: bool = False
        self.scs: bool = False
        self.id: str = self.image + '/' + self.specialfile + '/' + self.checksum + '/' + self.name
        if len(self.id) > 255:
            self.id = self.id[-255:]
        self.logging = logging.getLogger(__name__)

    def add_to_database(self):
        """
        Add the binary object to the database if not already exists.
        """
        self.logging.info(f'Add {self.name} with checksum {self.checksum} and subimage {self.image} to database.')
        if type(self.error) is tuple:
            error_str = str(self.error)
        else:
            error_str = self.error
        params = self.name, self.image, self.specialfile, str(self.path), self.timestamp, self.checksum, \
                 self.unsafe_language, self.modified, error_str, self.multi_cfi, self.single_cfi, self.scs, self.id

        global_variables.cursor.execute(global_variables.binary_obj_query, params)
        global_variables.connection.commit()

    def update_database(self, ignore_unsafe=False, error_static_exit=False):
        """
        If option check_unsafe was used, the analysis is run regardless of the unsafe_language field and the values
        are updated accordingly.
        """

        if type(self.error) is tuple:
            error_str = str(self.error)
        else:
            error_str = self.error
        params = self.modified, error_str, self.multi_cfi, self.single_cfi, self.scs, self.id
        if ignore_unsafe:
            self.logging.info(f'Update results of {self.name} as check_unsafe option used.')
            global_variables.cursor.execute(global_variables.binary_update_query, params)
            global_variables.connection.commit()
        elif error_static_exit:
            self.logging.info(f'Update results of {self.name} as error_static_exit option used.')
            global_variables.cursor.execute(global_variables.binary_update_query, params)
            global_variables.connection.commit()

    def __calculate_checksum(self) -> str:
        """

        :return: String representation of binary's checksum
        """
        with open(self.path, 'rb') as file_to_check:
            data = file_to_check.read()
            return hashlib.md5(data).hexdigest()

    def __check_compiler(self) -> bool:
        """
        Check if the memory was compiled with gcc or clang -> memory-unsafe language.

        :return: Whether the binary was compiled from a memory-unsafe language
        """
        file_path = str(self.path).replace(' ', '\\ ')
        result_comment = subprocess.run(
            args=[f"readelf -p .comment {file_path} | grep -E -i 'gcc|clang' | wc -l"],
            shell=True,
            check=True, stdout=subprocess.PIPE)
        result_gcc = subprocess.run(
            args=[f"grep -a -o '.note.gnu.build-id' {file_path} | wc -l"],
            shell=True, stdout=subprocess.PIPE)
        return (int(result_comment.stdout) > 0) or (int(result_gcc.stdout) > 0)

    def __get_timestamp(self) -> str:
        """

        :return: String representation of binary's timestamp in format: YYYY-MM-DD hh:mm:ss
        """
        timestamp = time.ctime(os.path.getmtime(self.path))
        return time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(timestamp))

    def to_string(self):
        return f'Name: {self.name}\n ' \
               f'Id: {self.id}\n ' \
               f'Memory-unsafe language: {self.unsafe_language}\n ' \
               f'Call register modified: {self.modified}\n' \
               f'Path: {self.path}\n ' \
               f'Image: {self.image}\n ' \
               f'Checksum: {self.checksum}\n ' \
               f'Multi_CFI: {self.multi_cfi}\n ' \
               f'Single_CFI: {self.single_cfi}\n ' \
               f'ShadowCallStack: {self.scs} '
