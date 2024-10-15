import os
from configparser import ConfigParser


class DatabaseConfig:

    @staticmethod
    def read_db_config(filename='config.ini', section='mysql'):
        """
        Read and parse database config file.

        :param filename: Config file name
        :param section: mysql section
        :return: Database credentials
        """
        config_file = os.path.join(os.getcwd(), 'database', filename)
        parser = ConfigParser()
        parser.read(config_file)
        db = {}
        if parser.has_section(section):
            items = parser.items(section)
            for item in items:
                db[item[0]] = item[1]
        else:
            raise Exception('{0} not found in the {1} file'.format(section, config_file))
        return db
