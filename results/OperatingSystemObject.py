import global_variables


class OperatingSystemObject:

    def __init__(self, os_name: str, image_name: str):
        self.name: str = os_name
        self.version: str = image_name
        self.binaries_total: int = 0
        self.binaries_unsafe: int = 0
        self.single_cfi: int = 0
        self.multi_cfi: int = 0
        self.scs: int = 0

    def add_to_database(self):
        """
        Add Operating System object to database.
        :return:
        """
        params = self.name, self.version
        global_variables.cursor.execute(global_variables.os_obj_query, params)
        global_variables.connection.commit()

    def update_values(self):
        """
        Update the results after running analysis on all binaries.

        :param connection: Connection to the database containing results
        """
        self.binaries_total = self.__count_files(0)
        self.binaries_unsafe = self.__count_files(1)
        self.single_cfi = self.__count_files(2)
        self.multi_cfi = self.__count_files(3)
        self.scs = self.__count_files(4)
        self.__update_database()

    def __update_database(self):
        """
        Update the results after running analysis on all binaries in the database.

        :param connection: Connection to the database containing results
        """
        params = (self.binaries_total, self.binaries_unsafe, self.single_cfi, self.multi_cfi, self.scs, self.version)
        global_variables.cursor.execute(global_variables.os_update_query, params)
        global_variables.connection.commit()

    def __count_files(self, option: int) -> int:
        """
        Count how may files were analyzed, how many are relevant, have CFI or SCS.

        :param option: Option of what should be counted
        """
        params = self.version + '%',
        if option == 0:
            count_query = 'SELECT * FROM BinaryFile WHERE Subimage LIKE ?'
        elif option == 1:
            count_query = 'SELECT * FROM BinaryFile WHERE Unsafe_language = 1 AND Subimage LIKE ?'
        elif option == 2:
            count_query = 'SELECT * FROM BinaryFile WHERE Unsafe_language = 1 AND  Single_CFI = 1 AND Subimage LIKE ?'
        elif option == 3:
            count_query = 'SELECT * FROM BinaryFile WHERE Unsafe_language = 1 AND  Multi_CFI = 1 AND Subimage LIKE ?'
        elif option == 4:
            count_query = 'SELECT * FROM BinaryFile WHERE Unsafe_language = 1 AND  ShadowCallStack = 1 AND Subimage ' \
                          'LIKE ? '
        else:
            return 0
        global_variables.cursor.execute(count_query, params)
        return len(global_variables.cursor.fetchall())
