import global_variables


class ImageObject:
    def __init__(self, os_version: str, image_name: str):
        self.version: str = os_version
        self.name: str = image_name
        self.type: str = 'filesystem'
        self.id: str = os_version + '/' + image_name

    def add_to_database(self):
        """
        Add ImageObject to database if it does not exist yet.
        """
        params = self.version, self.name, self.type, self.id
        global_variables.cursor.execute(global_variables.image_obj_query, params)
        global_variables.connection.commit()
