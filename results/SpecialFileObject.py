from pathlib import Path
import global_variables


class SpecialFileObject:

    def __init__(self, image: str, file_name: str, file_type: str, path: Path):
        self.image: str = image
        self.name: str = file_name
        self.type: str = file_type
        self.path: Path = path
        self.id: str = image + '/' + file_name

    def add_to_database(self):
        """
        Add the binary object to the database if not already exists.

        :param connection: connection to database containing results
        :return:
        """
        params = self.image, self.name, self.type, str(self.path), self.id
        global_variables.cursor.execute(global_variables.specialfile_obj_query, params)
        global_variables.connection.commit()

