import logging
import subprocess
from pathlib import Path
from typing import List

from analysis.ImageAnalysis import ImageAnalysis
from finder.MagicValuesExtensions import MagicValues, FileExtensions
from mount.SparseImageMounter import SparseImageMounter
from mount.ExtImageMounter import ExtImageMounter
from mount.ApexPayloadMounter import ApexPayloadMounter
from finder.ElfBinariesFinder import ElfBinariesFinder
from results.ImageObject import ImageObject
from results.SpecialFileObject import SpecialFileObject
from finder.FormatsFinder import FormatsFinder


class AndroidImageAnalysis(ImageAnalysis):
    """
    Extract binaries, run checks/analysis, and add to database for Android images.
    """

    def __init__(self, distribution: str, factory_image_dir: Path,
                 ignore_unsafe: bool, error_static_exit: bool, only_multi_module: bool, skip_db_check: bool):
        self.image_top_dir: Path = factory_image_dir
        super().__init__(distribution, factory_image_dir,
                         ignore_unsafe, error_static_exit, only_multi_module, skip_db_check)

    def run(self):
        """
        Main function to run all analysis on the given image file.
        Establish the connection the database containing all analysis results.
        Find and mount all contained image files of different types.

        :return:
        """
        self.__delete_raw_images()
        self.os_obj.add_to_database()
        all_sparse_images: List[Path] = FormatsFinder.find_images(self.image_top_dir,
                                                                  MagicValues.ANDROID_SPARSE_IMG_MAGIC_VALUE,
                                                                  FileExtensions.NO_EXTENSION)
        all_ext_images: List[Path] = FormatsFinder.find_images(self.image_top_dir,
                                                               MagicValues.EXT_IMG_MAGIC_VALUE,
                                                               FileExtensions.NO_EXTENSION)

        for image_path in all_sparse_images:
            self.logging.info("Mounting %s", image_path.as_posix())
            self.image_obj = ImageObject(self.os_obj.version, image_path.name)
            self.image_obj.add_to_database()
            with SparseImageMounter(image_path) as mount_path:
                self.__run_checks(mount_path)

        for image_path in all_ext_images:
            self.logging.info("Mounting %s", image_path.as_posix())
            self.image_obj = ImageObject(self.os_obj.version, image_path.name)
            self.image_obj.add_to_database()
            with ExtImageMounter(image_path) as mount_path:
                self.__run_checks(mount_path)

        self.__delete_raw_images()
        self.logging.info(f'Finished analysis of {self.os_obj.version}')
        self.os_obj.update_values()

    def __run_checks(self, mount_path: Path):
        """
        Create list of binaries to be analyzed, including files contained in apex files.
        Triggers the actual checks.

        :param mount_path: Path to where the subimage is mounted
        """
        all_apex_images: List[Path] = FormatsFinder.find_images(self.image_top_dir,
                                                                MagicValues.JAVA_ARCHIVE,
                                                                FileExtensions.APEX_FILE_EXTENSION)
        all_elf_binaries: List[Path] = ElfBinariesFinder.find_all(mount_path)
        for apex_path in all_apex_images:
            self.special_file_obj = SpecialFileObject(self.image_obj.id, apex_path.name, 'apex', apex_path)
            self.special_file_obj.add_to_database()
            with ApexPayloadMounter(apex_path) as payload_path:
                all_apex_binaries: List[Path] = ElfBinariesFinder.find_all(payload_path)
                self.run_checker(all_apex_binaries, self.image_obj.id, self.special_file_obj.id)
        self.run_checker(all_elf_binaries, self.image_obj.id)

    def __delete_raw_images(self):
        """
        Delete the raw images generated when converting Android Sparse images (not always working correctly
        -> needs to be deleted manually).
        """
        self.logging.info('Deleting raw images.')
        path_raw = str(self.image_top_dir) + '/*_raw.img'
        subprocess.run([f'rm -rf {path_raw}'], shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
