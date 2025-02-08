from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class HttpPlainTransfer(Base):
    def scan(self):
        set_values_for_key(key='HTTPPLAINTRANSFER', zh='HTTP 明文传输检测',
                           en='HTTP Plaintext Check')
        set_values_for_key(key='HTTPCHECKINFO', zh='检测App是否使用HTTP明文传输',
                           en="Detect whether there are usage conditions for SQL Cipher")

        TITLE = get_value('HTTPPLAINTRANSFER')
        LEVEL = 2
        INFO = get_value('HTTPCHECKINFO')
        strline = cmdString(
            'grep -r -Eo "http://[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}:[0-9]\+"' + self.appPath
        )
        paths = getSmalis(os.popen(strline).readlines())
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(paths)).description()

register(HttpPlainTransfer)
