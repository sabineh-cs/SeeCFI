import logging
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory


class DebPackageExtractor:
    """
    Extract .deb packages to analyze contained binaries.
    """

    def __init__(self, deb_path: Path):
        self.__deb_package: Path = deb_path
        self.__tmp_dir_path: TemporaryDirectory = TemporaryDirectory(prefix='/mnt/temporary.extract/')

        self.logging = logging.getLogger(__name__)

    def __enter__(self) -> Path:
        self.__extract_deb_package()
        return Path(self.__tmp_dir_path.name)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.__tmp_dir_path is not None:
            self.__tmp_dir_path.cleanup()

    def __extract_deb_package(self):
        """
        Extract .deb package into temporary directory as mounted image is read-only.
        """
        self.logging.info(f'Extracting {self.__deb_package}')
        try:
            out = subprocess.run(["dpkg-deb -xv " + (str(self.__deb_package)).replace(' ', '\\ ') + " " + str(
                self.__tmp_dir_path.name)], shell=True, check=True, stdout=subprocess.PIPE, )
            logging.error(f'Stdterr: {out.stderr}, stdout: {out.stdout}')
        except subprocess.CalledProcessError as e:
            logging.error(f'Could not unpack deb package: {e}')

