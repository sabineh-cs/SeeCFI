from pathlib import Path
from mount.ImageMounter import ImageMounter


class SparseImageMounter(ImageMounter):
    """
    Mount images of Android Sparse image format.
    """

    def __init__(self, image_path: Path, mount_options='sparse'):
        """

        :param image_path: path to image to mount
        :param mount_options: set to 'sparse' by default
        """
        super().__init__(image_path, mount_options)
