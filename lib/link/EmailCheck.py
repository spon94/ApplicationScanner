from lib.translation import *
from ..Base import Base
from ..apk import register
from ..info import Info
from ..tools import *


class EmailCheck(Base):
    def scan(self):
        set_values_for_key(key='ANDROIDEMAILCHECKTITLE', zh='EMAIL泄露检测',
                           en='EMAIL leak detection')
        set_values_for_key(key='ANDROIDEMAILCHECHINFO', zh='检测App泄露的EMAIL',
                           en="Detect EMAIL leaked by App")

        TITLE = get_value('ANDROIDEMAILCHECKTITLE')
        LEVEL = 1
        INFO = get_value('ANDROIDEMAILCHECHINFO')

        strline = cmdString('grep -r -Eo \'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\' ' + self.appPath)
        out = os.popen(strline).readlines()
        results = []
        for item in out:
            if 'Binary file' in item or 'schemas.android.com' in item or 'android.googlesource.com' in item:
                continue
            results.append(item)
        Info(key=self.__class__, title=TITLE, level=LEVEL, info=INFO, result='\n'.join(results)).description()


#register(EmailCheck)
