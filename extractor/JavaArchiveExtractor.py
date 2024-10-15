from pathlib import Path
from zipfile import ZipFile


class JavaArchiveExtractor:
    """
    Extract Android JavaArchive .apex to analyze contained binaries.
    """
    __APEX_PAYLOAD_FILENAME = 'apex_payload.img'
    __CAPEX_APEX_FILENAME = 'original_apex'

    @staticmethod
    def extract(apex_path: Path, dest_path: Path) -> Path:
        """
        Extract files/binaries from .apex file.

        :param apex_path: path to .apex file
        :param dest_path: path to destination to where to extract .apex file
        :return: Path to destination
        """
        with ZipFile(apex_path, 'r') as zip_file:
            print(zip_file)
            for file_name in zip_file.namelist():
                if file_name == JavaArchiveExtractor.__CAPEX_APEX_FILENAME:
                    zip_file.extract(file_name, dest_path)
                    with ZipFile(dest_path / file_name, 'r') as capex_file:
                        for filename in capex_file.namelist():
                            if filename == JavaArchiveExtractor.__APEX_PAYLOAD_FILENAME:
                                capex_file.extract(filename, dest_path)
                                return dest_path / filename
                if file_name == JavaArchiveExtractor.__APEX_PAYLOAD_FILENAME:
                    zip_file.extract(file_name, dest_path)
                    return dest_path / file_name
