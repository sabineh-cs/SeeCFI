import logging
import subprocess
import magic
from pathlib import Path
from typing import Union


class ImageMounter:
    """
    Mount images based on given mount options.
    """

    EXT_MOUNT_OPTION: str = 'ext'
    SPARSE_MOUNT_OPTION: str = 'sparse'
    APEX_MOUNT_OPTION: str = 'apex'
    ISO_MOUNT_OPTION: str = 'iso'

    def __init__(self, image_path: Path, mount_options: str):
        self.__apex_mount_path: Union[Path, None] = None
        self.__image_path: Path = image_path
        self.__loop_device: Union[Path, None] = None
        self.__mount_path: Union[Path, None] = None
        self.__mount_options = mount_options
        self.__img_path: Union[Path, None] = None
        self.__delete_loop: bool = True
        self.__mounting_output: str = ''

        self.logging = logging.getLogger(__name__)

    def __enter__(self) -> Path:
        self.__mount_img()
        return self.__mount_path

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Unmount loop device and delete it if image is not Android Sparse image.
        """
        self.__unmount_img()

        if str(self.__loop_device).endswith('p1') and str(self.__loop_device) is not '/dev/loop1':
            self.__loop_device = Path(str(self.__loop_device)[:-2])

        if self.__check_multi_partitions():
            self.__delete_loop = True
        if self.__delete_loop:
            self.__delete_loop_device()

    def __mount_img(self):
        """
        Create and mount loop device.
        Set mount point of image.FILE_EXTENSION
        """
        if self.__mount_options == ImageMounter.SPARSE_MOUNT_OPTION:
            self.__img_path = self.__convert_sparse_img_to_img()
        elif self.__mount_options == ImageMounter.APEX_MOUNT_OPTION:
            self.__img_path = self.__apex_mount_path
        else:
            self.__img_path = self.__image_path

        self.__loop_device = self.__create_loop_device(self.__img_path)

        if self.__check_multi_partitions():
            self.__delete_loop = False
            self.__loop_device = Path(str(self.__loop_device) + 'p1')

        out = subprocess.run(['udisksctl mount -b ' + str(self.__loop_device) + ' -o ro'],
                                                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not out.returncode == 0:
            self.__mounting_output = out.stderr.decode()
            self.logging.info(f'Exit code {out.returncode}: Stderr {self.__mounting_output}')
        else:
            self.__mounting_output = out.stdout.decode()
            self.logging.info(f'Exit code {out.returncode}: Stdout {self.__mounting_output}')
        self.__mount_path = self.__extract_mount_dir()
        self.logging.info(f'Mounted {self.__loop_device} at {self.__mount_path}')

    def __unmount_img(self):
        """
        Unmount loop device.
        """
        self.logging.info(f'Unmounting {self.__loop_device}')
        subprocess.run(['udisksctl unmount -b ' + str(self.__loop_device)],
                       shell=True, check=True, stdout=subprocess.PIPE)

    def __create_loop_device(self, img_path: Path) -> Path:
        """
        Setup the loop device of the image to mount.

        :param img_path: path to image to mount
        :return: Path to created loop device
        """
        if self.__mount_options == ImageMounter.SPARSE_MOUNT_OPTION and magic.from_file(str(img_path)) == 'data':
            results = subprocess.run(['udisksctl loop-setup --offset=0x100000 -f ' + str(img_path)],
                                         shell=True, check=True, stdout=subprocess.PIPE)
        else:
            results = subprocess.run(['udisksctl loop-setup -f ' + str(img_path)],
                                 shell=True, check=True, stdout=subprocess.PIPE)
        return self.__extract_loop_device(str(results.stdout))

    def __delete_loop_device(self):
        """
        Delete the loop device. Only called if image was not Android Sparse image.
        """
        try:
            subprocess.run(['udisksctl loop-delete -b ' + str(self.__loop_device)],
                       shell=True, check=True, stdout=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            logging.error(f'No need to delete loop device: {e}')

    def __extract_mount_dir(self) -> Path:
        """
        Extract the path to the mount point of the loop device.
        Extraction process different for Android Sparse images.

        :param mount_output: output of mount command
        :return: Path to mount directory
        """
        tmp = self.__mounting_output.partition('/media')[1:]
        if 'already mounted' in self.__mounting_output:
            self.__delete_loop = False
            return Path(tmp[0] + tmp[1].replace("'.\n\n", ""))
        else:
            return Path(tmp[0] + tmp[1].replace("\n", ""))

    @staticmethod
    def __extract_loop_device(loop_output) -> Path:
        """
        Extract the path to the created loop device.

        :param loop_output: output of loop setup command
        :return: Path to loop device
        """
        tmp = loop_output.partition('/dev')[1:]
        return Path(tmp[0] + tmp[1].partition('.\\n')[0])

    def __convert_sparse_img_to_img(self) -> Path:
        """
        Convert Android Sparse image to ext format.

        :return: Path to converted image
        """
        raw_img_path = Path(str(self.__image_path) + '_raw.img')
        self.logging.info(f'Converting {self.__image_path} using sim2img')
        subprocess.run(['simg2img', self.__image_path, raw_img_path])
        return raw_img_path

    def __delete_raw_image(self):
        self.logging.info(f'Deleting {self.__img_path}.')
        subprocess.run(['rm -rf', self.__img_path])

    def __check_multi_partitions(self):
        """
        Check if the mounted images (loop device) contains multiple partitions.

        :return: Whether the loop device contains multiple partitions
        """
        results = subprocess.run(['ls ' + str(self.__loop_device) + '* | wc -l'],
                                 shell=True, check=True, stdout=subprocess.PIPE)
        return int(results.stdout) > 1

