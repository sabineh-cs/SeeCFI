import logging
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Union


class SquashfsExtractor:
    """
    Extract squashfs filesystems to analyze them.
    """

    def __init__(self, fs_file: Path):
        self.__fs_file: Path = Path(str(fs_file).replace(' ', '\\ '))
        self.__tmp_dir_path: TemporaryDirectory = TemporaryDirectory(prefix='/mnt/temporary.extract/')
        self.__extracted_dir: Union[Path, None] = None
        self.logging = logging.getLogger(__name__)

    def __enter__(self):
        try:
            self.__extract_squashsf_file()
        except Exception as e:
            print(f'That is expected: {e}')
        self.__extracted_dir = Path(str(self.__tmp_dir_path.name)) / Path('squashfs-root')
        return self.__extracted_dir

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.__tmp_dir_path is not None:
            self.__tmp_dir_path.cleanup()

    def __extract_squashsf_file(self):
        """
        Extract the filesystem into a temporary directory.

        :return: Path to temporary directory containing extracted squashfs system
        """
        self.__copy_squashsf()
        fs_path: Path = Path(str(self.__tmp_dir_path.name)) / self.__fs_file.name
        self.logging.info(f'Extracting {self.__fs_file} to {self.__tmp_dir_path.name}')
        subprocess.run([f'unsquashfs -no -d {self.__tmp_dir_path.name}/squashfs-root {fs_path}'], shell=True, check=True)
        return fs_path

    def __copy_squashsf(self):
        """
        Copy squashfs file to temporary directory as mounted images is read-only.
        """
        self.logging.info(f'Copying {self.__fs_file} to {self.__tmp_dir_path.name}')
        subprocess.run([f'cp {self.__fs_file} {self.__tmp_dir_path.name}'], shell=True, check=True, stdout=subprocess.PIPE)

