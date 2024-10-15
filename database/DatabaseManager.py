from typing import Union

from mysql.connector import MySQLConnection
from database.DatabaseConfig import DatabaseConfig


class DatabaseManager:
    """
    Establish connection to database containing results and close in the end.
    """

    def __init__(self):
        self.db_config: {} = DatabaseConfig.read_db_config()
        self.connection: Union[MySQLConnection, None] = None

    def __enter__(self):
        self.connection: MySQLConnection = MySQLConnection(**self.db_config)
        return self.connection

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection is not None:
            if self.connection.is_connected():
                self.connection.close()

