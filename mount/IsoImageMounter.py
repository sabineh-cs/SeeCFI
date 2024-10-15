from pathlib import Path
from mount.ImageMounter import ImageMounter


class IsoImageMounter(ImageMounter):
    """
    Mount images of ISO image format.
    """

    def __init__(self, image_path: Path, mount_options='iso'):
        """

        :param image_path: path to image to mount
        :param mount_options: set to 'iso' by default
        """
        super().__init__(image_path, mount_options)