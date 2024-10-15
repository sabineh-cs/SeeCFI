from mysql.connector import MySQLConnection
from database.DatabaseConfig import DatabaseConfig

global connection
global cursor

os_obj_query = 'INSERT IGNORE INTO OperatingSystem (OS_Name, Version) VALUES (?, ?)'

os_update_query = 'UPDATE OperatingSystem SET Binaries_total = ?, Binaries_unsafe = ?, Single_CFI = ?, Multi_CFI = ?, ' \
                       'ShadowCallStack = ? WHERE Version = ?'

image_obj_query = 'INSERT IGNORE INTO Image (Version, ImageName, ImageType, Id) VALUES (?, ?, ?, ?)'

specialfile_obj_query = 'INSERT IGNORE INTO SpecialFile (Subimage, SpecialFileName, SpecialFileType, SpecialFilePath, ' \
                        'Id) VALUES (?, ?, ?, ?, ?) '

binary_obj_query = 'INSERT INTO BinaryFile (BinaryName, Subimage, SpecialFileTag, BinaryPath, FileTimestamp, Checksum, ' \
                   'Unsafe_language, Modified, Error, Multi_CFI, Single_CFI, ShadowCallStack, Id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) '

binary_update_query = 'UPDATE BinaryFile SET Modified = ?, Error = ?, Multi_CFI = ?, Single_CFI = ?, ShadowCallStack = ? WHERE Id = ?'


def setup_global_variables():
    global connection
    global cursor

    db_config: {} = DatabaseConfig.read_db_config()
    connection = MySQLConnection(**db_config)
    cursor = connection.cursor(prepared=True)


def cleanup_global_variables():
    global connection
    global cursor

    cursor.close()
    connection.close()
