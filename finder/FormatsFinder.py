from pathlib import Path
from typing import List

from finder.FileFinder import FileFinder
from finder.MagicValuesExtensions import MagicValues, FileExtensions


class FormatsFinder:
    """
    Find and list all files of a given format (can be special to operating system).
    """

    @staticmethod
    def find_images(image_path: Path, magic_value: MagicValues, file_extension: FileExtensions) -> List[Path]:
        """
        Find all images in the given path and subdirectories based on their magic value and extension.

        :param file_extension: file extension of a file indicating its file type
        :param magic_value: magic value of a file indicating its file type
        :param image_path: top directory given as user input
        :return:  List of paths to all images of given type
        """
        image_file_finder = FileFinder(
            dir_path=image_path,
            magic_value_prefix=magic_value,
            file_extension=file_extension)
        return image_file_finder.find_all()
