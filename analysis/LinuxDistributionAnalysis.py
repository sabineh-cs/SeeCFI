from pathlib import Path
from typing import List

from analysis.ImageAnalysis import ImageAnalysis
from extractor.SquashfsExtractor import SquashfsExtractor
from extractor.DebPackageExtractor import DebPackageExtractor
from finder.ElfBinariesFinder import ElfBinariesFinder
from finder.FormatsFinder import FormatsFinder
from finder.MagicValuesExtensions import FileExtensions, MagicValues
from results.ImageObject import ImageObject
from mount.IsoImageMounter import IsoImageMounter
from results.SpecialFileObject import SpecialFileObject


class LinuxDistributionAnalysis(ImageAnalysis):
    """
        Extract binaries, run checks/analysis, and add to database.
    """

    def __init__(self, distribution: str, factory_image_dir: Path,
                 ignore_unsafe: bool, error_static_exit: bool, only_multi_module: bool, skip_db_check: bool):
        super().__init__(distribution, factory_image_dir,
                         ignore_unsafe, error_static_exit, only_multi_module, skip_db_check,
                         linux=True)

    def run(self):
        """
        Main function to run all analysis on the given image file.
        Establish the connection the database containing all analysis results.
        Find and mount all contained image files of different types.
        """
        self.os_obj.add_to_database()

        # for image_path in all_iso_images:
        self.logging.info("Mounting %s", self.image_top_dir.as_posix())
        self.image_obj = ImageObject(self.os_obj.version, self.image_top_dir.name)
        self.image_obj.add_to_database()
        with IsoImageMounter(self.image_top_dir) as mount_path:
            all_squashfs_files: List[Path] = FormatsFinder.find_images(image_path=mount_path,
                                                                       magic_value=MagicValues.SQUASHSF_MAGIC_VALUE,
                                                                       file_extension=FileExtensions.NO_EXTENSION)
            for squash_fs in all_squashfs_files:
                with SquashfsExtractor(squash_fs) as unsquashed_path:
                    print('running checks')
                    self.logging.info(f'Runing checks {unsquashed_path}')
                    self.__run_checks(unsquashed_path)
            self.__run_checks(mount_path, )

        self.logging.info(f'Finished analysis of {self.os_obj.version}')
        self.os_obj.update_values()

    def __run_checks(self, mount_path: Path):
        """
        Create list of binaries to be analyzed, including files contained in apex files.
        Triggers the actual checks.

        :param mount_path: Path to where the subimage is mounted
        """
        self.logging.info(f'path to find binaries: {mount_path}')
        all_deb_packages: List[Path] = FormatsFinder.find_images(mount_path,
                                                                 MagicValues.DEB_MAGIC_VALUE,
                                                                 FileExtensions.DEB_FILE_EXTENSION)
        all_elf_binaries: List[Path] = ElfBinariesFinder.find_all(mount_path)
        print(all_elf_binaries)
        self.logging.info(f'Binaries to test: {all_elf_binaries}')
        for deb_path in all_deb_packages:
            self.special_file_obj = SpecialFileObject(self.image_obj.id, deb_path.name, 'deb', deb_path)
            self.special_file_obj.add_to_database()
            with DebPackageExtractor(deb_path) as payload_path:
                all_deb_binaries: List[Path] = ElfBinariesFinder.find_all(payload_path)
                self.run_checker(all_deb_binaries, self.image_obj.id, self.special_file_obj.id)
        self.run_checker(all_elf_binaries, self.image_obj.id)
