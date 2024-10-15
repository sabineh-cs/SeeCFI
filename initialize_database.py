import global_variables

OPERATING_SYSTEM_TABLE: str = 'CREATE TABLE IF NOT EXISTS OperatingSystem (OS_Name varchar(255), Version varchar(' \
                              '255), Binaries_total int, Binaries_unsafe int, Single_CFI int, Multi_CFI int, ' \
                              'ShadowCallStack int, PRIMARY KEY (Version), UNIQUE (Version)); '
IMAGE_TABLE: str = 'CREATE TABLE IF NOT EXISTS Image (Version varchar(255), ImageName varchar(255), ImageType ' \
                   'varchar(255), Id varchar(255), PRIMARY KEY (Id), UNIQUE (Id), FOREIGN KEY (Version) REFERENCES ' \
                   'OperatingSystem(Version)); '
SPECIAL_FILE_TABLE: str = 'CREATE TABLE IF NOT EXISTS SpecialFile (Subimage varchar(255), SpecialFileName varchar(' \
                          '255), SpecialFileType varchar(255), SpecialFilePath varchar(255), Id varchar(255), ' \
                          'PRIMARY KEY (Id), UNIQUE (Id), FOREIGN KEY (Subimage) REFERENCES Image(Id)); '
BINARY_FILE_TABLE: str = 'CREATE TABLE IF NOT EXISTS BinaryFile (BinaryName varchar(255), Subimage varchar(255), ' \
                         'SpecialFileTag varchar(255), BinaryPath varchar(255), FileTimestamp varchar(255), ' \
                         'Checksum varchar(255), Error text, Unsafe_language bool, Modified bool, Single_CFI bool, Multi_CFI bool, ' \
                         'ShadowCallStack bool, Id varchar(255), PRIMARY KEY (Id), UNIQUE (Id), FOREIGN KEY (' \
                         'Subimage) REFERENCES Image(Id));'


def creating_tables():
    cursor = global_variables.connection.cursor()
    cursor.execute(OPERATING_SYSTEM_TABLE)
    cursor.execute(IMAGE_TABLE)
    cursor.execute(SPECIAL_FILE_TABLE)
    cursor.execute(BINARY_FILE_TABLE)
    global_variables.connection.commit()


def initialize_database():
    try:
        creating_tables()
    except Exception as err:
        print(f'DATABASE ERROR: Could not initialize database (tables) because of {err}')
