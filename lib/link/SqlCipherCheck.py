from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class SQLCipherCheck(Base):
    def scan(self):
        set_values_for_key(key='SQLCIPHERTITLE', zh='SQLCIPHER加密检测',
                           en='SQL Ciphe check')
        set_values_for_key(key='SQLCHECHINFO', zh='检测App是否使用SqlCipher对数据库进行加密',
                           en="Detect whether there are usage conditions for SQL Cipher")

        TITLE = get_value('SQLCIPHERTITLE')
        LEVEL = 2
        INFO = get_value('SQLCHECHINFO')

        strline = cmdString(
            f'grep -r "Landroid/database/sqlite/SQLiteDatabase" {self.appPath} | cut -d \"/\" -f6-'
        )
        paths = getSmalis(os.popen(strline).readlines())
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(paths)).description()


register(SQLCipherCheck)
