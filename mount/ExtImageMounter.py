from pathlib import Path

from mount.ImageMounter import ImageMounter


class ExtImageMounter(ImageMounter):
    """
    Mount images of ext2 and ext4 format.
    """

    def __init__(self, image_path: Path, mount_options='ext'):
        """

        :param image_path: path to image to mount
        :param mount_options: set to 'ext' by default
        """
        super().__init__(image_path, mount_options)
