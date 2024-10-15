from pathlib import Path

from extractor.JavaArchiveExtractor import JavaArchiveExtractor
from mount.ExtImageMounter import ExtImageMounter
from tempfile import TemporaryDirectory


class ApexPayloadMounter(ExtImageMounter):
    """
    Mount and unpack APEX files.
    """

    def __init__(self, apex_path: Path, mount_options='apex'):
        """
        Mount and unpack APEX files.

        :param apex_path: path to apex file to unpack and mount
        :param mount_options: Set to 'apex' by default
        """
        super().__init__(apex_path, mount_options)
        self.tmp_dir_path: TemporaryDirectory = TemporaryDirectory(prefix='/mnt/temporary.extract/')
        self.apex_path = apex_path

    def __enter__(self) -> Path:
        """
        Unpack apex file (java archive).
        """
        apex_payload_path: Path = JavaArchiveExtractor.extract(self.apex_path, self.tmp_dir_path.name)
        self._image_path = self.apex_path
        self.__apex_mount_path = apex_payload_path
        return super().__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.tmp_dir_path.cleanup()
        super().__exit__(exc_type, exc_val, exc_tb)

